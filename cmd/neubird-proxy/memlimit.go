package main

import (
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/neubirdai/neubird-proxy/internal/proxy"
)

// cgroupFiles hold the container's memory limit: cgroup v2, then v1.
var cgroupFiles = []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"}

// memoryLimit returns the container's memory limit in bytes, or 0 if there
// is none (or it can't be read).
func memoryLimit(files []string) int64 {
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 || n >= 1<<60 { // "max", or v1's "no limit"
			return 0
		}
		return n
	}
	return 0
}

// applyMemoryLimit sizes response buffering to the container's memory
// limit and, unless GOMEMLIMIT is set, tells the Go runtime about it, so
// garbage is collected before the container is killed rather than after.
func applyMemoryLimit(srv *proxy.Server, maxBody int64, log *slog.Logger) {
	limit := memoryLimit(cgroupFiles)
	if limit == 0 {
		return
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(limit / 10 * 9)
	}
	capped := srv.SetMemoryLimit(limit)
	log.Info("memory limit", "limit_mib", limit>>20, "buffered_bodies_mib", limit/4*3>>20, "max_buffered_body_mib", capped>>20)
	if capped < maxBody {
		log.Warn("risky configuration", "detail", "responses over "+strconv.FormatInt(capped>>20, 10)+
			" MiB are refused (body_too_large), below max_body_bytes, to fit the memory limit; raise the limit to buffer up to max_body_bytes")
	}
}
