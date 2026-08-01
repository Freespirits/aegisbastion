// worker-passive (doc 02 §2.2): passive-source connector pool — passive DNS
// aggregators, subdomain sources, BGP/RDAP. Zero target contact (R0): every
// request goes to a third-party data source through the netguard egress
// guard.
package main

import (
	"github.com/aegisbastion/aegisbastion/services/discover/internal/runtime"
	"github.com/aegisbastion/aegisbastion/services/discover/internal/worker"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

func main() {
	worker.MainPool("discover-worker-passive", model.LanePassive, runtime.PoolPassive)
}
