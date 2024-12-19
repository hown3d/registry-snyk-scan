package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/distribution/notifications"
	imagev1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stackitcloud/registry-snyk-scan/types"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	httpServer *http.Server
	eventChan  chan<- types.RegistryEvent
}

func NewServer(port int, eventChan chan<- types.RegistryEvent) (*Server, error) {
	mux := http.NewServeMux()
	mux.Handle("POST /event", handleRegistryNotification(eventChan))
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	return &Server{
		httpServer: httpServer,
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return s.httpServer.ListenAndServe()
	})
	g.Go(func() error {
		<-gCtx.Done()
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(timeoutCtx)
	})
	return g.Wait()
}

func handleRegistryNotification(eventChan chan<- types.RegistryEvent) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var envelope notifications.Envelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "error decoding request body: %s", err)
			return
		}
		processEnvelope(envelope, eventChan)
		w.WriteHeader(http.StatusOK)
	}
}

func processEnvelope(envelope notifications.Envelope, eventChan chan<- types.RegistryEvent) {
	for _, event := range filterEvents(envelope.Events) {
		eventChan <- types.RegistryEventFromNotificationsEvent(&event)
	}
}

var knownManifestMediaTypes = []string{
	schema2.MediaTypeManifest,
	imagev1.MediaTypeImageManifest,
}

func filterEvents(events []notifications.Event) []notifications.Event {
	// filter out all events that are not push actions
	events = slices.DeleteFunc(events, func(e notifications.Event) bool {
		return e.Action != notifications.EventActionPush
	})

	// filter out non manifest mediaTypes
	events = slices.DeleteFunc(events, func(e notifications.Event) bool {
		return !slices.Contains(knownManifestMediaTypes, e.Target.MediaType)
	})

	return events
}
