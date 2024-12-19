package main

import (
	"flag"
	"log"
	"log/slog"

	"github.com/stackitcloud/registry-snyk-scan/controller"
	"github.com/stackitcloud/registry-snyk-scan/types"
	"github.com/stackitcloud/registry-snyk-scan/webhook"
	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

var port = flag.Int("port", 8080, "port to bind server to")

func main() {
	flag.Parse()
	ctx := signals.SetupSignalHandler()

	channel := make(chan event.TypedGenericEvent[types.RegistryEvent])

	mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{})
	if err != nil {
		log.Fatal(err)
	}
	if err := (&controller.Reconciler{}).AddToManager(mgr, channel); err != nil {
		log.Fatal(err)
	}

	s, err := webhook.NewServer(*port)
	if err != nil {
		log.Fatalf("error creating webhook server: %s", err)
	}
	slog.Info("serving", "port", port)

	var errg errgroup.Group

	errg.Go(func() error {
		return s.ListenAndServe(ctx)
	})
	errg.Go(func() error {
		return mgr.Start(ctx)
	})

	if err := errg.Wait(); err != nil {
		log.Fatal(err)
	}
}
