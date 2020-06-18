// +build amd64
// +build !nocontainers

package main

import (
	"context"
	"strconv"
	"strings"

	dockertypes "github.com/docker/docker/api/types"
	dockerclient "github.com/docker/docker/client"
	"github.com/golang/groupcache/lru"
	"github.com/spf13/viper"
)

func init() {
	RegisterExtraParser(func(config *viper.Viper) (ExtraParser, error) {
		if config.GetBool("extras.containers.enabled") {
			cp, err := NewContainerParser(config.Sub("extras.containers"))
			if err == nil {
				l.Printf("ContainerParser enabled (docker=%v pid_cache=%d docker_cache=%d)\n",
					cp.docker != nil,
					cacheSize(cp.pidCache),
					cacheSize(cp.dockerCache),
				)
			}
			return cp, err
		}
		return nil, nil
	})
}

type ContainerParser struct {
	docker *dockerclient.Client

	// map[int]string
	//	(pid -> containerID)
	pidCache Cache
	// map[string]dockertypes.ContainerJSON
	//	(containerID -> dockerResponse)
	dockerCache Cache
}

type Cache interface {
	Add(lru.Key, interface{})
	Get(lru.Key) (interface{}, bool)
}

type NoCache struct{}

func (NoCache) Add(lru.Key, interface{})        {}
func (NoCache) Get(lru.Key) (interface{}, bool) { return nil, false }

// NewCache returns an lru.Cache if size is >0, NoCache otherwise
func NewCache(size int) Cache {
	if size > 0 {
		return lru.New(size)
	}
	return NoCache{}
}

func cacheSize(c Cache) int {
	switch x := c.(type) {
	case *lru.Cache:
		return x.MaxEntries
	}
	return 0
}

func NewContainerParser(config *viper.Viper) (*ContainerParser, error) {
	var docker *dockerclient.Client
	if config.GetBool("docker") {
		version := config.GetString("docker_api_version")
		if version == "" {
			// > Docker does not recommend running versions prior to 1.12, which
			// > means you are encouraged to use an API version of 1.24 or higher.
			// https://docs.docker.com/develop/sdk/#api-version-matrix
			version = "1.24"
		}
		var err error
		docker, err = dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithVersion(version))
		if err != nil {
			return nil, err
		}
	}

	return &ContainerParser{
		docker:      docker,
		pidCache:    NewCache(config.GetInt("pid_cache")),
		dockerCache: NewCache(config.GetInt("docker_cache")),
	}, nil
}

// Find `pid=` in a message and adds the container ids to the Extra object
func (c ContainerParser) Parse(am *AuditMessage) {
	switch am.Type {
	case 1300, 1326:
		am.Containers = c.getContainersForPid(getPid(am.Data))
	}
}

func getPid(data string) (pid, ppid int) {
	start := 0
	end := 0
	var err error

	for {
		if start = strings.Index(data, "pid="); start < 0 {
			return
		}

		// Progress the start point beyon the = sign
		start += 4
		if end = strings.IndexByte(data[start:], spaceChar); end < 0 {
			// There was no ending space, maybe the pid is at the end of the line
			end = len(data) - start

			// If the end of the line is greater than 7 characters away (overflows 22 bit uint) then it can't be a pid
			// > On 64-bit systems, pid_max can be set to any value up to 2^22 (PID_MAX_LIMIT, approximately 4 million).
			if end > 7 {
				return
			}
		}

		id := data[start : start+end]
		if start > 4 && data[start-5] == 'p' {
			ppid, err = strconv.Atoi(id)
		} else {
			pid, err = strconv.Atoi(id)
		}
		if err != nil {
			el.Printf("Failed to parse pid: %s: %v\n", id, err)
		}
		if pid != 0 && ppid != 0 {
			return
		}

		data = data[start+end:]
	}
}

func (c ContainerParser) getContainersForPid(pid, ppid int) map[string]string {
	if pid == 0 {
		return nil
	}
	cid, err := c.getPidContainerID(pid)
	if err != nil {
		// pid might have exited before we could check it, try the ppid
		return c.getContainersForPid(ppid, 0)
	}

	if cid == "" {
		return nil
	}

	if c.docker != nil {
		container, err := c.getDockerContainer(cid)

		if err != nil {
			el.Printf("failed to query docker for container id: %s: %v\n", cid, err)
		} else {
			return map[string]string{
				"id":            cid,
				"image":         container.Config.Image,
				"name":          container.Config.Labels["io.kubernetes.container.name"],
				"pod_uid":       container.Config.Labels["io.kubernetes.pod.uid"],
				"pod_name":      container.Config.Labels["io.kubernetes.pod.name"],
				"pod_namespace": container.Config.Labels["io.kubernetes.pod.namespace"],
			}
		}
	}

	return map[string]string{
		"id": cid,
	}
}

func (c ContainerParser) getPidContainerID(pid int) (string, error) {
	if v, found := c.pidCache.Get(pid); found {
		return v.(string), nil
	}
	cid, err := processContainerID(pid)
	if err == nil {
		c.pidCache.Add(pid, cid)
	}
	return cid, err
}

func (c ContainerParser) getDockerContainer(containerID string) (dockertypes.ContainerJSON, error) {
	if v, found := c.dockerCache.Get(containerID); found {
		return v.(dockertypes.ContainerJSON), nil
	}

	container, err := c.docker.ContainerInspect(context.TODO(), containerID)
	if err == nil {
		c.dockerCache.Add(containerID, container)
	}
	return container, err
}
