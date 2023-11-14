//go:build !nocontainers
// +build !nocontainers

// NOTE: This code was originally sourced from:
//
//     https://github.com/capsule8/capsule8
//
// But this repository was removed, so we have vendored just these functions
// that we need, with the original license intact.

// Copyright 2018 Capsule8, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// controlGroup describes the cgroup membership of a process
type controlGroup struct {
	// Unique hierarchy ID
	ID int

	// Cgroup controllers (subsystems) bound to the hierarchy
	Controllers []string

	// Path is the pathname of the control group to which the process
	// belongs. It is relative to the mountpoint of the hierarchy.
	Path string
}

// processContainerID returns the container ID running the specified process.
// If the process is not running inside of a container, the return will be the
// empty string.
func processContainerID(pid int) (string, error) {
	cgroups, err := taskControlGroups(pid, pid)
	if err != nil {
		return "", err
	}

	for _, cg := range cgroups {
		if id := containerID(cg.Path); id != "" {
			return id, nil
		}
	}

	return "", nil
}

// TaskControlGroups returns the cgroup membership of the specified task.
func taskControlGroups(tgid, pid int) ([]controlGroup, error) {
	filename := fmt.Sprintf("/proc/%d/task/%d/cgroup", tgid, pid)
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cgroups []controlGroup

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		t := scanner.Text()
		parts := strings.Split(t, ":")
		var ID int
		ID, err = strconv.Atoi(parts[0])
		if err != nil {
			// glog.Warningf("Couldn't parse cgroup line: %s", t)
			continue
		}

		c := controlGroup{
			ID:          ID,
			Controllers: strings.Split(parts[1], ","),
			Path:        parts[2],
		}

		cgroups = append(cgroups, c)
	}

	return cgroups, nil
}

// Historical note:
// procfs.FileSystem.ProcessContainerID was initially written to use a regex
// to determine whether a cgroup path was for a container:
//
// Docker cgroup paths may look like either of:
// - /docker/[CONTAINER_ID]
// - /kubepods/[...]/[CONTAINER_ID]
// - /system.slice/docker-[CONTAINER_ID].scope
//
// const cgroupContainerPattern = "^(/docker/|/kubepods/.*/|/system.slice/docker-)([[:xdigit:]]{64})(.scope|$)"
//
// I've elected to not continue using this method, because it is inherently
// fragile. We can see here that Docker has already changed its format at least
// once. It also fails to work for anything other than Docker. Other container
// environments are not accounted for. More frustratingly, LXC, for example,
// even allows runtime customization of cgroup paths.
//
// What does not appear to be so fragile is that container IDs always have a
// sha256 hash in them. So we're going to look for sha256 strings.

func isHexDigit(r rune) bool {
	if r >= '0' && r <= '9' {
		return true
	}
	if r >= 'A' && r <= 'F' {
		return true
	}
	if r >= 'a' && r <= 'f' {
		return true
	}
	return false
}

// sha256.Size is sha256 size in bytes. Hexadecimal representation doubles that
const sha256HexSize = sha256.Size * 2

func isSHA256(s string) bool {
	if len(s) != sha256HexSize {
		return false
	}
	for _, c := range s {
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

// ContainerID returns the ContainerID extracted from the given string. The
// string may simply be a container ID or it may be a full cgroup controller
// path with a container ID embedded in it. If the given string contains no
// discernable container ID, the return will be "".
func containerID(s string) string {
	paths := strings.Split(s, "/")
	for _, p := range paths {
		if isSHA256(p) {
			return p
		}
		if len(p) > sha256HexSize {
			// Does it start with a sha256?
			x := p[:sha256HexSize]
			if !isHexDigit(rune(p[sha256HexSize])) && isSHA256(x) {
				return x
			}
			// Does it end with a sha256?
			p = strings.TrimSuffix(p, ".scope")
			x = p[len(p)-sha256HexSize:]
			if !isHexDigit(rune(p[len(p)-sha256HexSize-1])) && isSHA256(x) {
				return x
			}
		}
	}
	return ""
}
