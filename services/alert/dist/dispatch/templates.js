/**
 * Message templates (doc 05 §10: Handlebars, sandboxed — no helpers that do
 * I/O; §12: render errors fall back to plain text and the incident still
 * delivers). Structured channel payloads are built by the adapters; these
 * templates produce the human text fragments inside them.
 */
import Handlebars from "handlebars";
const TEMPLATES = {
    incident_card: "*{{sev}}* {{incident.title}}\n{{#each alerts}}{{this.description}}\n{{/each}}asset: {{incident.asset.identifier}}{{#if incident.asset.criticality}} ({{incident.asset.criticality}}){{/if}} • incident {{incident.incidentId}} • alerts: {{incident.alertCount}}{{#if mention}} {{mention}}{{/if}}",
    still_firing: "still firing (×{{incident.alertCount}}): *{{sev}}* {{incident.title}} — incident {{incident.incidentId}}",
    escalation: "ESCALATION: *{{sev}}* {{incident.title}} is unacknowledged — incident {{incident.incidentId}}{{#if mention}} {{mention}}{{/if}}",
    digest: "alert digest for {{incident.orgId}}: {{incident.alertCount}} alert(s) in the current storm window, latest: {{incident.title}} ({{incident.incidentId}})",
    notify: "{{#each alerts}}{{this.title}}\n{{this.description}}{{/each}}{{#if note}}\n{{note}}{{/if}}",
    plain: "{{incident.title}} — {{#each alerts}}{{this.description}}{{/each}}",
};
const compiled = new Map();
function templateFor(name) {
    const key = TEMPLATES[name] !== undefined ? name : "plain";
    let t = compiled.get(key);
    if (!t) {
        // No helper registration, no partials, no I/O — sandboxed per doc 05 §10.
        t = Handlebars.compile(TEMPLATES[key], { noEscape: true, strict: true });
        compiled.set(key, t);
    }
    return t;
}
const SEV_BADGE = {
    critical: "[CRITICAL]",
    high: "[HIGH]",
    medium: "[MEDIUM]",
    low: "[LOW]",
    info: "[INFO]",
};
export function renderText(template, ctx) {
    const full = { ...ctx, sev: SEV_BADGE[ctx.incident.severity] ?? `[${ctx.incident.severity}]` };
    try {
        return { text: templateFor(template)(full) };
    }
    catch (err) {
        // §12 template render error → plain-text fallback, incident still delivered.
        try {
            return {
                text: templateFor("plain")(full),
                renderError: err.message,
            };
        }
        catch {
            return { text: `${ctx.incident.title} (incident ${ctx.incident.incidentId})`, renderError: err.message };
        }
    }
}
