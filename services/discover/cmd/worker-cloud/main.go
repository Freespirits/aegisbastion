// worker-cloud (doc 02 §2.2): credentialed-cloud pool — AWS Resource
// Explorer + Organizations, Azure Resource Graph, GCP Cloud Asset Inventory.
// Read-only by construction (doc 02 §6.3): only List|Get|Describe|Search
// calls pass the SDK middleware; customer credentials are resolved per
// tenant at task time, never carried in task payloads.
package main

import (
	"github.com/aegisbastion/aegisbastion/services/discover/internal/runtime"
	"github.com/aegisbastion/aegisbastion/services/discover/internal/worker"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

func main() {
	worker.MainPool("discover-worker-cloud", model.LaneCloud, runtime.PoolCloud)
}
