package types

import (
	"fmt"
	"net/url"

	"github.com/docker/distribution/notifications"
	"github.com/opencontainers/go-digest"
)

type RegistryEvent struct {
	Registry   string
	Repository string
	Tag        string
	Digest     digest.Digest
}

func (e RegistryEvent) Reference() string {
	return fmt.Sprintf("%s/%s:%s@%s", e.Registry, e.Repository, e.Tag, e.Digest)
}

func RegistryEventFromNotificationsEvent(e *notifications.Event) RegistryEvent {
	u, err := url.Parse(e.Target.URL)
	if err != nil {
		panic(err)
	}

	return RegistryEvent{
		Repository: e.Target.Repository,
		Tag:        e.Target.Tag,
		Registry:   u.Host,
		Digest:     e.Target.Digest,
	}
}
