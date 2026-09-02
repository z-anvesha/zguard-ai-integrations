/*
 * process-verdict.js — Phase 6: decide the outcome and build the block response.
 *
 * Reads the canonical aiguard.* variables from EV-ParseAIGuardVerdict and the
 * callout status, then sets:
 *   aiguard.outcome        "allow" | "block"
 *   aiguard.block.body     response payload   (when block)
 *   aiguard.block.status   HTTP status        (when block)
 *   aiguard.block.ctype    Content-Type       (when block)
 *
 * The block body matches the *caller's* dialect — Vertex/Gemini, OpenAI
 * chat/completions, OpenAI Responses, Anthropic messages, or MCP JSON-RPC — and,
 * for streaming callers, is a graceful SSE refusal so the client session is not
 * broken. Blocks return the caller's native shape with HTTP 200 and an
 * `x-aiguard-blocked: true` header unless blockStatus forces a hard status.
 *
 * The verdict is reported exactly as the API returned it: the detector names in
 * the block message come from detectorResponses, and this flow never decides on
 * its own whether a detector "really" blocked.
 */

var apiType  = context.getVariable('aiguard.apiType');
var phase    = context.getVariable('aiguard.cfg.phase');
var failOpen = context.getVariable('aiguard.cfg.failOpen') === 'true';
var model    = context.getVariable('aiguard.model') || 'model';
var severity = context.getVariable('aiguard.severity') || '';
var policyNm = context.getVariable('aiguard.policyName') || '';
var trId     = context.getVariable('aiguard.transactionId') || context.getVariable('aiguard.txnId') || '';
var descriptions = aiguardParse(context.getVariable('aiguard.cfg.descriptions')) || {};

var reqBody = aiguardParse(context.getVariable('request.content'));
var _spath = String(context.getVariable('proxy.pathsuffix') || context.getVariable('request.uri') || '').toLowerCase();
// Streaming callers must get an SSE refusal, not JSON. Detect from the request
// body flag (OpenAI/Anthropic native set stream:true) or from the endpoint
// itself: Gemini streamGenerateContent and Vertex :streamRawPredict make the
// stream the endpoint rather than a body field, which the flag alone misses.
var streaming = (reqBody && reqBody.stream === true) ||
    _spath.indexOf('streamgeneratecontent') !== -1 ||
    _spath.indexOf(':streamrawpredict') !== -1;

/* ---- llm flavour (for the right block shape) ----------------------------- */
function llmFlavor() {
    var p = String(context.getVariable('proxy.pathsuffix') || context.getVariable('request.uri') || '').toLowerCase();
    if (/\/responses$/.test(p)) { return 'openai-responses'; }
    if (p.indexOf('/v1/messages') !== -1 || p.indexOf('/anthropic/') !== -1) { return 'anthropic'; }
    return 'openai-chat';
}

/* ---- did the scan produce a usable verdict? ------------------------------ *
 * Two ways it may not have: a non-200 from the callout, or a 200 whose body
 * carries no action -- which is how the API reports a soft failure such as
 * statusCode 404 "Policy not found". Neither is permission.
 */
var scStatus = Number(context.getVariable('aiguardScanResponse.status.code') || 0);
var action = aiguardNormalizeAction(context.getVariable('aiguard.action'));

if (scStatus !== 200 || !aiguardHasVerdict(action)) {
    if (failOpen) { context.setVariable('aiguard.outcome', 'allow'); }
    else { buildFailClosed(); }
} else if (action === 'BLOCK') {
    context.setVariable('aiguard.outcome', 'block');
    buildBlock();
} else {
    // ALLOW, and DETECT which is monitor-only: reported, not enforced.
    context.setVariable('aiguard.outcome', 'allow');
}

/* ================================================================== *
 * Detector helpers
 * ================================================================== */

// Names the API reported as blocking, else as triggered. Reported verbatim.
function detectorNames() {
    var blocking  = context.getVariable('aiguard.blockingDetectors') || '';
    var triggered = context.getVariable('aiguard.triggeredDetectors') || '';
    var raw = blocking.length ? blocking : triggered;
    if (aiguardIsBlank(raw)) { return []; }
    return String(raw).split(',');
}

function detectedThreatList() {
    var names = detectorNames(), out = [], seen = {};
    for (var i = 0; i < names.length; i++) {
        var key = String(names[i]).replace(/^\s+|\s+$/g, '');
        if (!key.length || seen[key]) { continue; }
        seen[key] = true;
        // An unknown detector falls back to its own name, so a detector added
        // upstream still produces a sensible message without a bundle change.
        out.push(descriptions[key] || key);
    }
    return out;
}

// A single category label for the x-aiguard-category header.
function category() {
    var names = detectorNames();
    return names.length ? String(names[0]).replace(/^\s+|\s+$/g, '') : 'policy';
}

/* ================================================================== *
 * Block builders (format-aware)
 * ================================================================== */
function noticeText() {
    var threats = detectedThreatList();
    var head = 'ZSCALER AI GUARD SECURITY ALERT: ' +
        ((phase === 'response') ? 'RESPONSE BLOCKED' : 'REQUEST BLOCKED');
    return head + (threats.length ? (': ' + threats.join(', ')) : '');
}

function put(body, status, ctype) {
    // blockStatus knob: force a hard status on non-streaming native-200 blocks so
    // blocks show up in status-code metrics. SSE stays 200 (a stream needs it);
    // fail-closed (status 500) is untouched since the override only fires on 200.
    var eff = status;
    if (status === 200 && ctype !== 'text/event-stream') {
        var bs = context.getVariable('aiguard.cfg.blockStatus');
        if (bs && bs !== 'native' && /^[0-9]+$/.test(String(bs))) { eff = parseInt(bs, 10); }
    }
    context.setVariable('aiguard.block.body', body);
    context.setVariable('aiguard.block.status', String(eff));
    context.setVariable('aiguard.block.ctype', ctype);
    context.setVariable('aiguard.block.reason',
        eff === 200 ? 'OK' : (eff === 403 ? 'Forbidden' : (eff >= 500 ? 'Internal Server Error' : 'Blocked')));
}

function aiguardObj(cat) {
    return { action: 'BLOCK', severity: severity, policyName: policyNm,
             detectors: detectorNames(), transactionId: trId };
}

function buildBlock() {
    var notice = noticeText();
    var cat = category();
    context.setVariable('aiguard.block.category', cat);

    if (apiType === 'mcp') {
        put(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: '🛡️ ' + notice } }),
            200, 'application/json');
        return;
    }
    if (apiType === 'gemini') {
        put(JSON.stringify({
            candidates: [{ content: { role: 'model', parts: [{ text: notice }] }, finishReason: 'STOP' }],
            modelVersion: model, aiguard: aiguardObj(cat)
        }), 200, 'application/json');
        return;
    }
    var flavor = llmFlavor();
    if (streaming) { put(buildLlmSSE(flavor, notice), 200, 'text/event-stream'); return; }

    if (flavor === 'anthropic') {
        put(JSON.stringify({
            id: 'msg_aiguard_block', type: 'message', role: 'assistant', model: model,
            content: [{ type: 'text', text: notice }], stop_reason: 'end_turn', stop_sequence: null,
            usage: { input_tokens: 0, output_tokens: 0 }, aiguard: aiguardObj(cat)
        }), 200, 'application/json');
    } else if (flavor === 'openai-responses') {
        put(JSON.stringify({
            id: 'resp_aiguard_block', object: 'response', model: model,
            output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: notice }] }],
            aiguard: aiguardObj(cat)
        }), 200, 'application/json');
    } else { // openai-chat
        put(JSON.stringify({
            id: 'chatcmpl-aiguard-block', object: 'chat.completion', model: model,
            choices: [{ index: 0, message: { role: 'assistant', content: notice }, finish_reason: 'stop' }],
            usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }, aiguard: aiguardObj(cat)
        }), 200, 'application/json');
    }
}

// Graceful streaming refusal so the caller's SSE parser completes cleanly
// instead of erroring mid-stream.
function buildLlmSSE(flavor, notice) {
    var sb = [];
    if (flavor === 'openai-chat' || flavor === 'openai-responses') {
        var id = 'chatcmpl-aiguard-block', obj = 'chat.completion.chunk';
        sb.push('data: ' + JSON.stringify({ id: id, object: obj, model: model,
            choices: [{ index: 0, delta: { role: 'assistant', content: notice }, finish_reason: null }] }));
        sb.push('data: ' + JSON.stringify({ id: id, object: obj, model: model,
            choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] }));
        sb.push('data: [DONE]');
        return sb.join('\n\n') + '\n\n';
    }
    function ev(type, obj) { return 'event: ' + type + '\ndata: ' + JSON.stringify(obj); }
    sb.push(ev('message_start', { type: 'message_start', message: { id: 'msg_aiguard_block',
        type: 'message', role: 'assistant', model: model, content: [], stop_reason: null,
        stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } } }));
    sb.push(ev('content_block_start', { type: 'content_block_start', index: 0,
        content_block: { type: 'text', text: '' } }));
    sb.push(ev('content_block_delta', { type: 'content_block_delta', index: 0,
        delta: { type: 'text_delta', text: notice } }));
    sb.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
    sb.push(ev('message_delta', { type: 'message_delta',
        delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 0 } }));
    sb.push(ev('message_stop', { type: 'message_stop' }));
    return sb.join('\n\n') + '\n\n';
}

/* ================================================================== *
 * Fail-closed (no usable verdict, failOpen=false)
 * ================================================================== */
function buildFailClosed() {
    context.setVariable('aiguard.outcome', 'block');
    context.setVariable('aiguard.block.category', 'scanner-unavailable');
    var st = Number(context.getVariable('aiguardScanResponse.status.code') || 0);
    var detail;
    if (st && st !== 200) {
        detail = 'HTTP ' + st;
    } else if (st === 200) {
        // A 200 with no action: the body carries the reason, e.g. statusCode 404
        // "Policy not found" when policyId names a policy this key cannot use.
        var em = context.getVariable('aiguard.errorMsg') || '';
        var sc = context.getVariable('aiguard.statusCode') || '';
        detail = 'no verdict returned' +
            (aiguardIsBlank(sc) ? '' : ' (statusCode ' + sc + ')') +
            (aiguardIsBlank(em) ? '' : ': ' + em);
    } else {
        detail = 'AI Guard API unreachable';
    }
    var msg = '🛡️ ZSCALER AI GUARD SECURITY ALERT: Security scan did not complete (' +
        detail + '). Request blocked for safety.';
    if (apiType === 'mcp') {
        put(JSON.stringify({ jsonrpc: '2.0', error: { code: -32603, message: msg } }),
            200, 'application/json');
    } else {
        put(JSON.stringify({ error: msg }), 500, 'application/json');
    }
}
