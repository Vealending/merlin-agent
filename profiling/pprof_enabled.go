//go:build pprof

package profiling

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/Ne0nd0g/merlin-agent/v2/cli"
)

func Start() {
	cli.Message(cli.NOTE, "pprof profiling enabled, starting server on 127.0.0.1:6060")
	go func() {
		if err := http.ListenAndServe("127.0.0.1:6060", nil); err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("pprof server error: %s", err))
		}
	}()
}
