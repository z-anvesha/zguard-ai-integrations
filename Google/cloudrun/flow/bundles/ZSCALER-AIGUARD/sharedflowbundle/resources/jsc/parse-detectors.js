/*
 * parse-detectors.js — flatten detectorResponses into flow variables.
 *
 * The detection response carries detectorResponses as an object keyed by
 * detector name, which ExtractVariables' JSONPath cannot enumerate. This walks
 * it once and publishes two comma-separated name lists:
 *
 *   aiguard.triggeredDetectors   every detector that fired
 *   aiguard.blockingDetectors    those whose action is BLOCK
 *
 * Both are reported exactly as the API returned them. A detector can carry
 * action=BLOCK while triggered is false — that is the policy's configured
 * action, and it is the policy's decision to make, not this flow's.
 */

var parsed = aiguardParse(context.getVariable('aiguardScanResponse.content'));
var dets = (parsed && parsed.detectorResponses) ? parsed.detectorResponses : null;
var out = aiguardDetectors(dets);

context.setVariable('aiguard.triggeredDetectors', out.triggered.join(','));
context.setVariable('aiguard.blockingDetectors', out.blocking.join(','));
