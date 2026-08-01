// Package ctypes is the single source of truth for the change_type v1 enum
// (doc 03 §5.2): proto mapping, alertable classification (doc 03 §5.3), and
// alert category mapping. Kept separate so diff, events, alert mapping, and
// the enum-coverage test all share one table.
package ctypes

import (
	"strings"

	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"
)

// Groups of doc 03 §5.2.
const (
	GroupAsset    = "asset"
	GroupDNS      = "dns"
	GroupTLS      = "tls"
	GroupHTTP     = "http"
	GroupPort     = "port"
	GroupCloud    = "cloud"
	GroupDrift    = "drift"
	GroupExposure = "exposure"
	GroupMeta     = "meta"
)

// Entry describes one change_type v1 value.
type Entry struct {
	// Type is the wire string, e.g. "tls.cert_expiring".
	Type string
	// Proto is the monitorv1 enum value.
	Proto monitorv1.ChangeType
	// Group is the doc 03 §5.2 group.
	Group string
	// Alertable reports membership in the doc 03 §5.3 alertable set
	// (asset.new only on high-criticality scope — see AlertableFor).
	Alertable bool
	// Category is the AlertEvent v1 category when alertable (doc 03 §5.3:
	// exposure|config-drift|new-asset per change group).
	Category string
}

// V1 is the complete change_type v1 table (30 values + UNSPECIFIED handled by
// proto). Port and cloud groups are Later producers (doc 03 §14) but are
// fully mapped here so downstream consumers see the complete enum semantics.
var V1 = []Entry{
	{"asset.new", monitorv1.ChangeType_CHANGE_TYPE_ASSET_NEW, GroupAsset, true, "new-asset"},
	{"asset.removed", monitorv1.ChangeType_CHANGE_TYPE_ASSET_REMOVED, GroupAsset, false, ""},
	{"asset.reactivated", monitorv1.ChangeType_CHANGE_TYPE_ASSET_REACTIVATED, GroupAsset, false, ""},
	{"dns.records_changed", monitorv1.ChangeType_CHANGE_TYPE_DNS_RECORDS_CHANGED, GroupDNS, false, ""},
	{"dns.dangling_cname", monitorv1.ChangeType_CHANGE_TYPE_DNS_DANGLING_CNAME, GroupDNS, true, "exposure"},
	{"dns.new_records", monitorv1.ChangeType_CHANGE_TYPE_DNS_NEW_RECORDS, GroupDNS, false, ""},
	{"dns.ns_changed", monitorv1.ChangeType_CHANGE_TYPE_DNS_NS_CHANGED, GroupDNS, false, ""},
	{"tls.cert_changed", monitorv1.ChangeType_CHANGE_TYPE_TLS_CERT_CHANGED, GroupTLS, false, ""},
	{"tls.cert_expiring", monitorv1.ChangeType_CHANGE_TYPE_TLS_CERT_EXPIRING, GroupTLS, false, ""},
	{"tls.cert_expired", monitorv1.ChangeType_CHANGE_TYPE_TLS_CERT_EXPIRED, GroupTLS, true, "exposure"},
	{"tls.protocol_downgrade", monitorv1.ChangeType_CHANGE_TYPE_TLS_PROTOCOL_DOWNGRADE, GroupTLS, true, "exposure"},
	{"tls.hostname_mismatch", monitorv1.ChangeType_CHANGE_TYPE_TLS_HOSTNAME_MISMATCH, GroupTLS, true, "exposure"},
	{"http.status_changed", monitorv1.ChangeType_CHANGE_TYPE_HTTP_STATUS_CHANGED, GroupHTTP, false, ""},
	{"http.title_changed", monitorv1.ChangeType_CHANGE_TYPE_HTTP_TITLE_CHANGED, GroupHTTP, false, ""},
	{"http.content_changed", monitorv1.ChangeType_CHANGE_TYPE_HTTP_CONTENT_CHANGED, GroupHTTP, false, ""},
	{"http.headers_changed", monitorv1.ChangeType_CHANGE_TYPE_HTTP_HEADERS_CHANGED, GroupHTTP, false, ""},
	{"http.tech_added", monitorv1.ChangeType_CHANGE_TYPE_HTTP_TECH_ADDED, GroupHTTP, false, ""},
	{"http.tech_removed", monitorv1.ChangeType_CHANGE_TYPE_HTTP_TECH_REMOVED, GroupHTTP, false, ""},
	{"http.redirect_target_changed", monitorv1.ChangeType_CHANGE_TYPE_HTTP_REDIRECT_TARGET_CHANGED, GroupHTTP, false, ""},
	{"port.opened", monitorv1.ChangeType_CHANGE_TYPE_PORT_OPENED, GroupPort, false, ""},
	{"port.closed", monitorv1.ChangeType_CHANGE_TYPE_PORT_CLOSED, GroupPort, false, ""},
	{"cloud.config_drift", monitorv1.ChangeType_CHANGE_TYPE_CLOUD_CONFIG_DRIFT, GroupCloud, false, ""},
	{"cloud.resource_new", monitorv1.ChangeType_CHANGE_TYPE_CLOUD_RESOURCE_NEW, GroupCloud, false, ""},
	{"cloud.resource_removed", monitorv1.ChangeType_CHANGE_TYPE_CLOUD_RESOURCE_REMOVED, GroupCloud, false, ""},
	{"baseline.drift", monitorv1.ChangeType_CHANGE_TYPE_BASELINE_DRIFT, GroupDrift, true, "config-drift"},
	{"baseline.drift_resolved", monitorv1.ChangeType_CHANGE_TYPE_BASELINE_DRIFT_RESOLVED, GroupDrift, false, ""},
	{"exposure.opened", monitorv1.ChangeType_CHANGE_TYPE_EXPOSURE_OPENED, GroupExposure, true, "exposure"},
	{"exposure.closed", monitorv1.ChangeType_CHANGE_TYPE_EXPOSURE_CLOSED, GroupExposure, true, "exposure"},
	{"monitor.probe_failing", monitorv1.ChangeType_CHANGE_TYPE_MONITOR_PROBE_FAILING, GroupMeta, false, ""},
	{"monitor.change_burst", monitorv1.ChangeType_CHANGE_TYPE_MONITOR_CHANGE_BURST, GroupMeta, false, ""},
}

var byType = func() map[string]Entry {
	m := make(map[string]Entry, len(V1))
	for _, e := range V1 {
		m[e.Type] = e
	}
	return m
}()

var byProto = func() map[monitorv1.ChangeType]Entry {
	m := make(map[monitorv1.ChangeType]Entry, len(V1))
	for _, e := range V1 {
		m[e.Proto] = e
	}
	return m
}()

// Lookup returns the entry for a wire change_type string.
func Lookup(t string) (Entry, bool) { e, ok := byType[t]; return e, ok }

// LookupProto returns the entry for a proto enum value.
func LookupProto(p monitorv1.ChangeType) (Entry, bool) { e, ok := byProto[p]; return e, ok }

// AlertableFor applies doc 03 §5.3: the alertable set is all exposure.*,
// baseline.drift, dns.dangling_cname, tls.cert_expired,
// tls.hostname_mismatch, tls.protocol_downgrade, and asset.new on
// high-criticality scope only.
func AlertableFor(changeType, assetCriticality string) bool {
	e, ok := byType[changeType]
	if !ok || !e.Alertable {
		return false
	}
	if e.Type == "asset.new" {
		return assetCriticality == "high" || assetCriticality == "critical"
	}
	return true
}

// GroupOf returns the doc 03 §5.2 group of a wire change_type string
// (prefix-based, safe for unknown future types).
func GroupOf(changeType string) string {
	if i := strings.Index(changeType, "."); i > 0 {
		return changeType[:i]
	}
	return changeType
}
