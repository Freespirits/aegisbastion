/**
 * Minimal in-process metrics (doc 05 §14) rendered in Prometheus text format
 * for GET /v1/metrics. No client library — the metric set is small and the
 * exposition format is trivial; counters are labeled via serialized keys.
 */
export class Metrics {
    counters = new Map();
    latency = new Map();
    static key(name, labels) {
        const suffix = Object.entries(labels)
            .sort(([a], [b]) => (a < b ? -1 : 1))
            .map(([k, v]) => `${k}="${v.replace(/"/g, '\\"')}"`)
            .join(",");
        return suffix === "" ? name : `${name}{${suffix}}`;
    }
    inc(name, labels = {}, by = 1) {
        const k = Metrics.key(name, labels);
        this.counters.set(k, (this.counters.get(k) ?? 0) + by);
    }
    observeLatency(name, labels, ms) {
        const k = Metrics.key(name, labels);
        const agg = this.latency.get(k) ?? { count: 0, sumSeconds: 0 };
        agg.count += 1;
        agg.sumSeconds += ms / 1000;
        this.latency.set(k, agg);
    }
    // --- doc 05 §14 convenience methods --------------------------------------
    ingest(module) {
        this.inc("herald_ingest_total", { module });
    }
    dedupVerdict(verdict) {
        this.inc("herald_dedup_verdicts_total", { verdict });
    }
    routeDecision(policyIds) {
        for (const p of policyIds)
            this.inc("herald_route_decisions_total", { policy: p });
    }
    delivery(channel, status, latencyMs) {
        this.inc("herald_delivery_total", { channel, status });
        if (status === "sent" && latencyMs !== undefined) {
            this.observeLatency("herald_delivery_latency_seconds", { channel }, latencyMs);
        }
    }
    escalationFire(step) {
        this.inc("herald_escalation_fires_total", { step: String(step) });
    }
    authzReject(reason) {
        this.inc("herald_authz_rejects_total", { reason });
    }
    /** Prometheus text exposition (gauges supplied by the caller per scrape). */
    render(gauges = {}) {
        const lines = [];
        for (const [k, v] of [...this.counters.entries()].sort())
            lines.push(`${k} ${v}`);
        for (const [k, agg] of [...this.latency.entries()].sort()) {
            lines.push(`${k.replace("{", "_count{").replace(/^([^{]+)$/, "$1_count")} ${agg.count}`);
            lines.push(`${k.replace("{", "_sum{").replace(/^([^{]+)$/, "$1_sum")} ${agg.sumSeconds.toFixed(6)}`);
        }
        for (const [k, v] of Object.entries(gauges))
            lines.push(`${k} ${v}`);
        return lines.join("\n") + "\n";
    }
}
