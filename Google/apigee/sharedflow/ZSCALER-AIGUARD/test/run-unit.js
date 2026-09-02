/*
 * run-unit.js — execute the SharedFlow's JavaScript outside Apigee.
 *
 * Apigee runs these on Rhino with a `context` object; this stubs that object so
 * the same files can be exercised under Node. It checks the parts that are pure
 * logic — config resolution, body construction, detector flattening and the
 * verdict decision — which is where a porting mistake actually lands.
 *
 *     node test/run-unit.js
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const JSC = path.join(__dirname, '..', 'sharedflowbundle', 'resources', 'jsc');
const LIB = fs.readFileSync(path.join(JSC, 'aiguard-lib.js'), 'utf8');

let pass = 0, fail = 0;
function check(name, ok, detail) {
    if (ok) { pass++; console.log('  [PASS] ' + name); }
    else { fail++; console.log('  [FAIL] ' + name + (detail ? ' -- ' + detail : '')); }
}

// Run one resource with a fresh variable bag, as a policy invocation would.
function run(resource, vars) {
    const bag = Object.assign({}, vars);
    const context = {
        getVariable: (k) => (k in bag ? bag[k] : null),
        setVariable: (k, v) => { bag[k] = v; }
    };
    const src = LIB + '\n' + fs.readFileSync(path.join(JSC, resource), 'utf8');
    vm.runInNewContext(src, { context, JSON, String, Number, Object, parseInt, RegExp });
    return bag;
}

console.log('\n-- config resolution -----------------------------------------');
let b = run('init-config.js', { 'aiguard.token': 'k' });
check('defaults: us1 endpoint', b['aiguard.cfg.endpoint'] === 'api.us1.zseclipse.net',
      b['aiguard.cfg.endpoint']);
check('defaults: prompt phase', b['aiguard.cfg.phase'] === 'prompt');
check('defaults: fail closed', b['aiguard.cfg.failOpen'] === 'false');
check('defaults: no policy pinned', b['aiguard.cfg.policyId'] === '');
check('key present', b['aiguard.cfg.keyMissing'] === 'false');

b = run('init-config.js', {});
check('missing key is flagged', b['aiguard.cfg.keyMissing'] === 'true');

b = run('init-config.js', { 'aiguard.token': 'k', 'aiguardCloud': 'eu1', 'type': 'response-prompt' });
check('cloud override', b['aiguard.cfg.endpoint'] === 'api.eu1.zseclipse.net', b['aiguard.cfg.endpoint']);
check('response phase', b['aiguard.cfg.phase'] === 'response');

console.log('\n-- scan body ------------------------------------------------');
b = run('build-aiguard-scan-body.js', {
    'aiguard.apiType': 'llm', 'aiguard.cfg.phase': 'prompt',
    'aiguard.promptText': 'hello', 'aiguard.cfg.policyId': ''
});
let body = JSON.parse(b['aiguardScanRequestBody']);
check('prompt scans IN', body.direction === 'IN' && body.content === 'hello', JSON.stringify(body));
check('no policyId when unpinned', !('policyId' in body));
check('no transactionId when not a UUID', !('transactionId' in body));

b = run('build-aiguard-scan-body.js', {
    'aiguard.apiType': 'llm', 'aiguard.cfg.phase': 'response',
    'aiguard.responseText': 'the reply', 'aiguard.cfg.policyId': '1152',
    'aiguard.txnId': '3fa85f64-5717-4562-b3fc-2c963f66afa6'
});
body = JSON.parse(b['aiguardScanRequestBody']);
check('response scans OUT', body.direction === 'OUT' && body.content === 'the reply');
check('policyId sent when pinned', body.policyId === 1152);
check('UUID transactionId is sent', body.transactionId === '3fa85f64-5717-4562-b3fc-2c963f66afa6');

b = run('build-aiguard-scan-body.js', {
    'aiguard.apiType': 'llm', 'aiguard.cfg.phase': 'prompt',
    'aiguard.promptText': '', 'aiguard.cfg.policyId': ''
});
check('empty content is flagged, never scanned', b['aiguard.contentCount'] === '0');

// A tool result re-entering the model is OUT -- the indirect-injection leg.
b = run('build-aiguard-scan-body.js', {
    'aiguard.apiType': 'mcp', 'aiguard.cfg.phase': 'prompt', 'aiguard.cfg.policyId': '',
    'aiguard.toolEvent': JSON.stringify({ tool: 'read_ticket', input: { id: 'T-1' }, output: 'open' })
});
body = JSON.parse(b['aiguardScanRequestBody']);
check('tool result scans OUT', body.direction === 'OUT', body.direction);
check('tool event scanned as values, not JSON',
      body.content.indexOf('{') === -1 && body.content.indexOf('read_ticket') !== -1, body.content);

console.log('\n-- detector flattening --------------------------------------');
b = run('parse-detectors.js', { 'aiguardScanResponse.content': JSON.stringify({
    detectorResponses: {
        pii: { triggered: false, action: 'BLOCK' },
        prompt_injection: { triggered: true, action: 'BLOCK' },
        toxicity: { triggered: true, action: 'ALLOW' }
    } }) });
check('triggered list', b['aiguard.triggeredDetectors'] === 'prompt_injection,toxicity',
      b['aiguard.triggeredDetectors']);
check('blocking list reported verbatim', b['aiguard.blockingDetectors'] === 'pii,prompt_injection',
      b['aiguard.blockingDetectors']);

console.log('\n-- verdict decision -----------------------------------------');
function verdict(vars) {
    return run('process-verdict.js', Object.assign({
        'aiguard.apiType': 'llm', 'aiguard.cfg.phase': 'prompt',
        'aiguard.cfg.failOpen': 'false', 'aiguard.cfg.blockStatus': 'native',
        'aiguard.cfg.descriptions': '{}', 'aiguardScanResponse.status.code': 200
    }, vars));
}
check('ALLOW passes', verdict({ 'aiguard.action': 'ALLOW' })['aiguard.outcome'] === 'allow');
check('DETECT is monitor-only, passes', verdict({ 'aiguard.action': 'DETECT' })['aiguard.outcome'] === 'allow');
check('BLOCK blocks', verdict({ 'aiguard.action': 'BLOCK' })['aiguard.outcome'] === 'block');
check('unknown action fails closed', verdict({ 'aiguard.action': 'WEIRD' })['aiguard.outcome'] === 'block');
check('no action fails closed', verdict({ 'aiguard.action': '' })['aiguard.outcome'] === 'block');
check('no action + failOpen passes',
      verdict({ 'aiguard.action': '', 'aiguard.cfg.failOpen': 'true' })['aiguard.outcome'] === 'allow');
check('callout failure fails closed',
      verdict({ 'aiguard.action': 'ALLOW', 'aiguardScanResponse.status.code': 503 })['aiguard.outcome'] === 'block');

// "Policy not found" arrives as HTTP 200 with an in-body statusCode.
b = verdict({ 'aiguard.action': '', 'aiguard.statusCode': '404', 'aiguard.errorMsg': 'Policy not found' });
check('soft 404 names the cause', b['aiguard.block.body'].indexOf('Policy not found') !== -1,
      b['aiguard.block.body']);

b = verdict({ 'aiguard.action': 'BLOCK', 'aiguard.blockingDetectors': 'prompt_injection',
              'aiguard.cfg.descriptions': JSON.stringify({ prompt_injection: 'Prompt injection detected' }) });
check('block names the detector', b['aiguard.block.body'].indexOf('Prompt injection detected') !== -1);
check('block is native 200 by default', b['aiguard.block.status'] === '200');

b = verdict({ 'aiguard.action': 'BLOCK', 'aiguard.cfg.blockStatus': '403' });
check('blockStatus forces a hard status', b['aiguard.block.status'] === '403');

console.log('\n%d checks, %d failed\n', pass + fail, fail);
process.exit(fail ? 1 : 0);
