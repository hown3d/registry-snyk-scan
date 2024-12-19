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
	"github.com/go-logr/logr"
	imagev1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stackitcloud/registry-snyk-scan/types"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

type Server struct {
	httpServer *http.Server
	eventChan  chan<- event.TypedGenericEvent[types.RegistryEvent]
	logger     logr.Logger
}

func NewServer(port int, eventChan chan<- event.TypedGenericEvent[types.RegistryEvent], logger logr.Logger) (*Server, error) {
	mux := http.NewServeMux()
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	s := &Server{
		httpServer: httpServer,
		logger:     logger,
		eventChan:  eventChan,
	}
	mux.Handle("POST /event", s.handleRegistryNotification())
	return s, nil
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

func (s *Server) handleRegistryNotification() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var envelope notifications.Envelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "error decoding request body: %s", err)
			return
		}
		s.processEnvelope(envelope)
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) processEnvelope(envelope notifications.Envelope) {
	for _, e := range filterEvents(envelope.Events) {
		registryEvent := types.RegistryEventFromNotificationsEvent(&e)
		s.logger.V(int(zap.DebugLevel)).Info("recieved event from registry", "notifications.Event", e, "registryEvent", registryEvent)
		s.eventChan <- event.TypedGenericEvent[types.RegistryEvent]{
			Object: registryEvent,
		}
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
