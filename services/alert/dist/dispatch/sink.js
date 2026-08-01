/**
 * Delivery sink abstraction — what makes deliveries MOCKABLE. The dispatcher
 * always writes the recorded outbox (alert.deliveries + payload snapshots);
 * whether bytes actually leave the process is the sink's decision:
 *   - RecordedSink: captures every send (tests, HERALD_DELIVERY_MODE=record).
 *   - LiveSink: fan-out to the five channel adapters (slack, teams,
 *     splunk-hec, syslog, webhook).
 */
/** Test/dev sink: every send recorded, nothing leaves the process. */
export class RecordedSink {
    mode = "record";
    sent = [];
    /** Test hook: force failures for specific channels. */
    failChannels = new Set();
    async send(req) {
        this.sent.push(structuredClone(req));
        if (this.failChannels.has(req.delivery.channel)) {
            return { ok: false, error: `recorded failure for ${req.delivery.channel}` };
        }
        return { ok: true, providerResponseCode: 200, latencyMs: 0, payloadSnapshot: { text: req.text } };
    }
    async close() { }
}
