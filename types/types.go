package types

import (
	"crypto/tls"
	"fmt"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"net/http"
	"net/url"

	"github.com/docker/distribution/notifications"
	"github.com/opencontainers/go-digest"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type RegistryEvent struct {
	Registry   string
	Repository string
	Tag        string
	Digest     digest.Digest
}

func (e RegistryEvent) Reference() string {
	if e.Digest == "" {
		return fmt.Sprintf("%s/%s:%s", e.Registry, e.Repository, e.Tag)
	}
	return fmt.Sprintf("%s/%s@%s", e.Registry, e.Repository, e.Digest)
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

func (e RegistryEvent) Platform() (v1.Platform, error) {
	ref, err := name.ParseReference(e.Reference())
	if err != nil {
		return v1.Platform{}, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithTransport(tr))
	if err != nil {
		return v1.Platform{}, err
	}

	configFile, err := img.ConfigFile()
	if err != nil {
		return v1.Platform{}, err
	}

	return v1.Platform{
		Architecture: configFile.Architecture,
		OS:           configFile.OS,
	}, nil
}
