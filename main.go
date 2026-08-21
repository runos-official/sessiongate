// Command sessiongate is the RunOS in-cluster session gate.
//
// It is a skeleton at this version: it prints its build version and exits 0,
// which is enough to prove the release pipeline, the image and the version
// stamping end to end before any session handling exists.
package main

import (
	"fmt"
	"os"

	"github.com/runos-official/sessiongate/version"
)

func main() {
	fmt.Printf("runos-session-gate %s\n", version.Version)
	os.Exit(0)
}
