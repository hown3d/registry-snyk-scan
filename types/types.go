package types

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"

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

// exposed for overriding in tests
var RemoteImage = remote.Image

func (e RegistryEvent) Platform(insecureRegistry bool) (v1.Platform, error) {
	ref, err := name.ParseReference(e.Reference())
	if err != nil {
		return v1.Platform{}, err
	}

	options := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}

	if insecureRegistry {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		options = append(options, remote.WithTransport(tr))
	}

	img, err := RemoteImage(ref, options...)
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
