/*
 * aiguard-lib.js — shared helpers for the ZSCALER-AIGUARD SharedFlow.
 *
 * Included (via <IncludeURL>jsc://aiguard-lib.js</IncludeURL>) into every JS
 * policy in this bundle, so its functions are in scope before each script's
 * own resource runs. Pure ES5 (Apigee's Rhino engine) — no const/let, arrow
 * functions, template literals, or Array.prototype extras beyond ES5.
 *
 * Everything here is deliberately defensive: a gateway security control must
 * never throw on a malformed body. Parsers return null/'' on failure and the
 * callers treat "couldn't parse" as "nothing to scan" (fail toward the
 * configured fail-open/closed posture), never as an unhandled 500.
 */

/* ------------------------------------------------------------------ *
 * JSON
 * ------------------------------------------------------------------ */

// Parse a JSON string, returning null (never throwing) on any failure.
function aiguardParse(str) {
    if (str === null || str === undefined || str === '') { return null; }
    try { return JSON.parse(str); } catch (e) { return null; }
}

// Compact JSON string of an object; '' on failure.
function aiguardStringify(obj) {
    try { return JSON.stringify(obj); } catch (e) { return ''; }
}

/* ------------------------------------------------------------------ *
 * Value collection
 *
 * Recursively walk any JSON value and push its scalar *values* (strings,
 * numbers, booleans) into acc — dropping keys, braces and punctuation. Feeding
 * AI Guard these natural values rather than serialized JSON is what keeps the
 * text detectors accurate on tool-call arguments and results: a JSON wrapper
 * reads as code and false-positives benign calls. See ARCHITECTURE.md.
 * ------------------------------------------------------------------ */
function aiguardCollect(node, acc) {
    if (node === null || node === undefined) { return; }
    var t = typeof node;
    if (t === 'string') { if (node.length) { acc.push(node); } return; }
    if (t === 'number' || t === 'boolean') { acc.push(String(node)); return; }
    if (Object.prototype.toString.call(node) === '[object Array]') {
        for (var i = 0; i < node.length; i++) { aiguardCollect(node[i], acc); }
        return;
    }
    if (t === 'object') {
        for (var k in node) {
            if (Object.prototype.hasOwnProperty.call(node, k)) { aiguardCollect(node[k], acc); }
        }
    }
}

// Convenience: collect a value's scalars and join them with a space.
function aiguardCollectJoined(node) {
    var acc = [];
    aiguardCollect(node, acc);
    return acc.join(' ');
}

/* ------------------------------------------------------------------ *
 * Headers
 * ------------------------------------------------------------------ */

// First value of a request header, or '' if absent. Apigee exposes the first
// header value at request.header.<name>; case-insensitive on the name.
function aiguardHeader(name) {
    var v = context.getVariable('request.header.' + name);
    return (v === null || v === undefined) ? '' : String(v);
}

/* ------------------------------------------------------------------ *
 * Agent-harness scaffolding
 *
 * Some coding agents inject <system-reminder>…</system-reminder> blocks into
 * user turns (harness context, not user intent). They are stripped from USER
 * text ONLY before scanning, so AI Guard judges the actual user input — never
 * from tool results or model output, which must reach the scanner byte for
 * byte. Non-greedy, multiline, case-insensitive.
 * ------------------------------------------------------------------ */
var AIGUARD_SYSREMINDER_RE = /<system-reminder>[\s\S]*?<\/system-reminder>/gi;

function aiguardStripReminders(text) {
    if (!text) { return ''; }
    try { return String(text).replace(AIGUARD_SYSREMINDER_RE, '').replace(/^\s+|\s+$/g, ''); }
    catch (e) { return String(text); }
}

/* ------------------------------------------------------------------ *
 * SSE / streaming helpers
 * ------------------------------------------------------------------ */

// Split a raw body into lines on CR/LF, dropping empties.
function aiguardSplitLines(raw) {
    if (!raw) { return []; }
    return String(raw).split(/[\r\n]+/);
}

// Strip a leading "data:" SSE prefix (with optional space) and trim.
function aiguardStripDataPrefix(line) {
    var t = String(line);
    t = t.replace(/^\s+|\s+$/g, '');
    if (t.indexOf('data:') === 0) { t = t.substring(5).replace(/^\s+|\s+$/g, ''); }
    return t;
}

/* ------------------------------------------------------------------ *
 * Verdict helpers
 * ------------------------------------------------------------------ */

function aiguardIsBlank(s) { return s === null || s === undefined || String(s) === ''; }

// ExtractVariables surfaces JSON booleans as the strings "true"/"false";
// normalise either form to a JS boolean.
function aiguardTruthy(v) { return v === true || v === 'true'; }

/*
 * The detection API answers 200 with an in-body statusCode for soft failures
 * (for example 404 "Policy not found" when policyId names a policy the key
 * cannot use). A response carrying no action is not permission — callers must
 * treat it as an unusable verdict and follow the fail-open/closed posture.
 */
function aiguardHasVerdict(action) {
    return !aiguardIsBlank(action);
}

/*
 * Normalise an action to the three the API returns. DETECT is AI Guard's
 * monitor-only verdict: it is reported and logged, and does not block.
 */
function aiguardNormalizeAction(action) {
    var a = aiguardIsBlank(action) ? '' : String(action).toUpperCase();
    if (a === 'BLOCK' || a === 'ALLOW' || a === 'DETECT') { return a; }
    return '';
}

/*
 * Names of the detectors in a detectorResponses object, split into those that
 * fired and those whose action is BLOCK. Reported exactly as the API returns
 * them — this flow enforces the policy's decision and never second-guesses it.
 */
function aiguardDetectors(detectorResponses) {
    var out = { triggered: [], blocking: [] };
    if (!detectorResponses || typeof detectorResponses !== 'object') { return out; }
    for (var name in detectorResponses) {
        if (!Object.prototype.hasOwnProperty.call(detectorResponses, name)) { continue; }
        var det = detectorResponses[name];
        if (!det || typeof det !== 'object') { continue; }
        if (aiguardTruthy(det.triggered)) { out.triggered.push(name); }
        if (!aiguardIsBlank(det.action) && String(det.action).toUpperCase() === 'BLOCK') {
            out.blocking.push(name);
        }
    }
    return out;
}
