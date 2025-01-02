package webhook

import (
	"context"
	"encoding/json"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema2"
	imagev1 "github.com/opencontainers/image-spec/specs-go/v1"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/docker/distribution/notifications"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stackitcloud/registry-snyk-scan/types"
	runtime_event "sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

type target struct {
	distribution.Descriptor
	Length         int64                     `json:"length,omitempty"`
	Repository     string                    `json:"repository,omitempty"`
	FromRepository string                    `json:"fromRepository,omitempty"`
	URL            string                    `json:"url,omitempty"`
	Tag            string                    `json:"tag,omitempty"`
	References     []distribution.Descriptor `json:"references,omitempty"`
}

func TestWebhook(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Webhook Suite")
}

var (
	server     *Server
	eventChan  chan runtime_event.TypedGenericEvent[types.RegistryEvent]
	ctx        context.Context
	cancelFunc context.CancelFunc
)

var _ = BeforeSuite(func() {
	eventChan = make(chan runtime_event.TypedGenericEvent[types.RegistryEvent], 1)
	logger := zap.New()
	var err error
	server, err = NewServer(8080, eventChan, logger)
	Expect(err).NotTo(HaveOccurred())

	ctx, cancelFunc = context.WithCancel(context.Background())
	go func() {
		err := server.ListenAndServe(ctx)
		Expect(err).NotTo(HaveOccurred())
	}()
})

var _ = AfterSuite(func() {
	cancelFunc()
})

var _ = Describe("Webhook", func() {
	It("should receive a RegistryEvent when sending a valid notifications.Envelope", func() {
		event := notifications.Event{
			ID:     "1234567890",
			Action: notifications.EventActionPush,
			Target: target{
				Descriptor: distribution.Descriptor{
					MediaType: "application/vnd.docker.distribution.manifest.v2+json",
					Size:      7143,
					Digest:    "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
				},
				Length:     7143,
				Repository: "my-repo",
				URL:        "https://my-registry/v2/my-repo/manifests/sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
				Tag:        "latest",
			},
			Request: notifications.RequestRecord{
				ID:     "9876543210",
				Addr:   "192.168.1.1:51234",
				Host:   "my-registry",
				Method: "PUT",
			},
			Timestamp: time.Date(2022, 1, 1, 12, 0, 0, 0, time.UTC),
		}

		eventJSON, err := json.Marshal(notifications.Envelope{Events: []notifications.Event{event}})
		Expect(err).NotTo(HaveOccurred())

		req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/event", io.NopCloser(strings.NewReader(string(eventJSON))))
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		Eventually(eventChan, 5*time.Second).Should(Receive(WithTransform(func(e runtime_event.TypedGenericEvent[types.RegistryEvent]) types.RegistryEvent {
			return e.Object
		}, Equal(types.RegistryEvent{
			Registry:   "my-registry",
			Repository: "my-repo",
			Tag:        "latest",
			Digest:     "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
		}))))
	})

	It("should return HTTP status code 400 when sending an invalid notifications.Envelope", func() {
		invalidEventJSON := `invalid json`

		req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/event", io.NopCloser(strings.NewReader(invalidEventJSON)))
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()

		Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
	})
})

var _ = Describe("FilterEvents", func() {
	It("should filter out non-push events and non-manifest media types", func() {
		events := []notifications.Event{
			{
				Action: notifications.EventActionPush,
				Target: target{
					Descriptor: distribution.Descriptor{
						MediaType: schema2.MediaTypeManifest,
					},
				},
			},
			{
				Action: notifications.EventActionPull,
				Target: target{
					Descriptor: distribution.Descriptor{
						MediaType: imagev1.MediaTypeImageManifest,
					},
				},
			},
			{
				Action: notifications.EventActionPush,
				Target: target{
					Descriptor: distribution.Descriptor{
						MediaType: "application/vnd.unknown.type",
					},
				},
			},
		}

		filteredEvents := filterEvents(events)

		Expect(len(filteredEvents)).To(Equal(1))
		Expect(filteredEvents[0].Action).To(Equal(notifications.EventActionPush))
		Expect(filteredEvents[0].Target.MediaType).To(Equal(schema2.MediaTypeManifest))
	})
})
