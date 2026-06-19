//go:build !nocontainers
// +build !nocontainers

package main

import (
	"context"

	containerdclient "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/golang/groupcache/lru"
	dockercontainer "github.com/moby/moby/api/types/container"
	dockerclient "github.com/moby/moby/client"
	"github.com/spf13/viper"
)

func init() {
	RegisterExtraParser(func(config *viper.Viper) (ExtraParser, error) {
		if config.GetBool("extras.containers.enabled") {
			cp, err := NewContainerParser(config.Sub("extras.containers"))
			if err == nil {
				l.Printf("ContainerParser enabled (docker=%v containerd=%v pid_cache=%d docker_cache=%d containerd_cache=%d)\n",
					cp.docker != nil,
					cp.containerd != nil,
					cacheSize(cp.pidCache),
					cacheSize(cp.dockerCache),
					cacheSize(cp.containerdCache),
				)
			}
			return cp, err
		}
		return nil, nil
	})
}

type ContainerParser struct {
	docker     *dockerclient.Client
	containerd *containerdclient.Client

	// map[int]string
	//	(pid -> containerID)
	pidCache Cache
	// map[string]dockertypes.ContainerJSON
	//	(containerID -> dockerResponse)
	dockerCache Cache
	// map[string]*containers.Container
	//	(containerID -> containerdResponse)
	containerdCache Cache
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
		ops := []dockerclient.Opt{dockerclient.FromEnv}
		if version := config.GetString("docker_api_version"); version != "" {
			ops = append(ops, dockerclient.WithAPIVersion(version))
		}
		var err error
		docker, err = dockerclient.New(ops...)
		if err != nil {
			return nil, err
		}
	}

	var containerdClient *containerdclient.Client
	if config.GetBool("containerd") {
		var opts []containerdclient.Opt
		sockAddr := config.GetString("containerd_sock")
		if sockAddr == "" {
			sockAddr = "/run/containerd/containerd.sock"
		}
		namespace := config.GetString("containerd_namespace")
		if namespace != "" {
			opts = append(opts, containerdclient.WithDefaultNamespace(namespace))
		}
		var err error
		containerdClient, err = containerdclient.New(sockAddr, opts...)
		if err != nil {
			return nil, err
		}
	}

	return &ContainerParser{
		docker:          docker,
		containerd:      containerdClient,
		pidCache:        NewCache(config.GetInt("pid_cache")),
		dockerCache:     NewCache(config.GetInt("docker_cache")),
		containerdCache: NewCache(config.GetInt("containerd_cache")),
	}, nil
}

// Find `pid=` in a message and adds the container ids to the Extra object
func (c ContainerParser) Parse(am *AuditMessage) {
	switch am.Type {
	case 1300, 1326:
		am.Containers = c.getContainersForPid(getPid(am.Data))
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

	if c.containerd != nil {
		container, err := c.getContainerdContainer(cid)

		if err != nil {
			el.Printf("failed to query containerd for container id: %s: %v\n", cid, err)
		} else {
			if container.Labels != nil {
				return map[string]string{
					"id":            cid,
					"image":         container.Image,
					"name":          container.Labels["io.kubernetes.container.name"],
					"pod_uid":       container.Labels["io.kubernetes.pod.uid"],
					"pod_name":      container.Labels["io.kubernetes.pod.name"],
					"pod_namespace": container.Labels["io.kubernetes.pod.namespace"],
				}
			} else {
				return map[string]string{
					"id":    cid,
					"image": container.Image,
				}
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

func (c ContainerParser) getDockerContainer(containerID string) (*dockercontainer.InspectResponse, error) {
	if v, found := c.dockerCache.Get(containerID); found {
		return v.(*dockercontainer.InspectResponse), nil
	}

	containerInspectResult, err := c.docker.ContainerInspect(context.TODO(), containerID, dockerclient.ContainerInspectOptions{})
	container := containerInspectResult.Container
	if err == nil {
		c.dockerCache.Add(containerID, &container)
	}
	return &container, err
}

func (c ContainerParser) getContainerdContainer(containerID string) (*containers.Container, error) {
	if v, found := c.containerdCache.Get(containerID); found {
		return v.(*containers.Container), nil
	}

	container, err := c.containerd.LoadContainer(context.TODO(), containerID)
	if err != nil {
		return nil, err
	}

	info, err := container.Info(context.TODO())
	if err != nil {
		return nil, err
	}

	c.containerdCache.Add(containerID, &info)

	return &info, nil
}
