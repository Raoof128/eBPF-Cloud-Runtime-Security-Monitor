package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ContainerMeta holds lightweight container data.
type ContainerMeta struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Runtime string `json:"runtime"`
}

// PodMeta represents Kubernetes metadata when available.
type PodMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Node      string `json:"node"`
}

var idRegex = regexp.MustCompile(`[0-9a-f]{32,64}`)

// LookupContainerMetadata reads /proc/<pid>/cgroup and takes the first long hex string in it
// as the container ID, which is where Docker and containerd put one. A process that has
// already exited, or that is not in a container, comes back as "host". This is a guess from
// the cgroup path, not a query to a container runtime.
func LookupContainerMetadata(pid int) ContainerMeta {
	path := filepath.Join("/proc", strconv.Itoa(pid), "cgroup")
	f, err := os.Open(path)
	if err != nil {
		return ContainerMeta{ID: "host", Name: "", Runtime: ""}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := idRegex.FindString(line); m != "" {
			return ContainerMeta{ID: m, Name: m[:12], Runtime: "cgroup"}
		}
	}
	return ContainerMeta{ID: "host", Name: "", Runtime: ""}
}

// LookupPodMeta returns the pod the AGENT runs in, from the environment variables the Helm
// chart sets (or the hostname). It is the same for every event: the agent does not ask the
// Kubernetes API which pod an event's process belongs to.
func LookupPodMeta() PodMeta {
	ns := getenv("POD_NAMESPACE", "default")
	name := getenv("POD_NAME", hostnameFallback())
	node := getenv("NODE_NAME", "node-unknown")
	return PodMeta{Name: name, Namespace: ns, Node: node}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hostnameFallback() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return strings.ReplaceAll(h, "\n", "")
}
