// worker-ct (doc 02 §2.2): Certificate Transparency pool — crt.sh batch
// search + Censys certificate search. (CT tail mode feeding Monitor is a
// doc 02 §8 Later item.)
package main

import (
	"github.com/aegisbastion/aegisbastion/services/discover/internal/runtime"
	"github.com/aegisbastion/aegisbastion/services/discover/internal/worker"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

func main() {
	worker.MainPool("discover-worker-ct", model.LaneCT, runtime.PoolCT)
}
