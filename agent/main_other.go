//go:build !linux

package main

import (
	"fmt"
	"os"
)

// eBPF is a Linux kernel feature. On other systems the rules and the event decoder still
// build and their tests still run, but there is nothing to attach to.
func main() {
	fmt.Fprintln(os.Stderr, "the agent only runs on Linux")
	os.Exit(1)
}
