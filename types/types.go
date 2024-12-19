package types

import (
	"fmt"
	"net/url"

	"github.com/docker/distribution/notifications"
	"github.com/opencontainers/go-digest"
	imagev1 "github.com/opencontainers/image-spec/specs-go/v1"
)

type RegistryEvent struct {
	Registry   string
	Repository string
	Tag        string
	Digest     digest.Digest
	Platform   *imagev1.Platform
}

func (e RegistryEvent) Reference() string {
	return fmt.Sprintf("%s/%s:%s@%s", e.Registry, e.Repository, e.Tag, e.Digest)
}

func RegistryEventFromNotificationsEvent(e *notifications.Event) RegistryEvent {
	platform := e.Target.Platform
	if platform == nil {
		platform = &imagev1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		}
	}

	u, err := url.Parse(e.Target.URL)
	if err != nil {
		panic(err)
	}

	return RegistryEvent{
		Platform:   platform,
		Repository: e.Target.Repository,
		Tag:        e.Target.Tag,
		Registry:   u.Host,
	}
}
