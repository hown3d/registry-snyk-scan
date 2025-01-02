package main

import (
	"errors"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/stackitcloud/registry-snyk-scan/controller"
	"github.com/stackitcloud/registry-snyk-scan/types"
	"github.com/stackitcloud/registry-snyk-scan/webhook"
	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

var (
	port             = flag.Int("port", 8081, "port to bind server to")
	namespace        = flag.String("namespace", "default", "namespace to deploy scan jobs into")
	insecureRegistry = flag.Bool("insecure-registry", false, "disables TLS verification for registry endpoint")
)

func main() {
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrllog.SetLogger(logger)

	ctx := signals.SetupSignalHandler()
	eventChan := make(chan event.TypedGenericEvent[types.RegistryEvent])

	mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				*namespace: {},
			},
		},
	})
	if err != nil {
		logger.Error(err, "creating new manager")
		os.Exit(1)
	}

	if err := (&controller.Reconciler{
		Namespace:        *namespace,
		InsecureRegistry: *insecureRegistry,
	}).AddToManager(mgr, eventChan); err != nil {
		logger.Error(err, "adding reconciler to manager")
		os.Exit(1)
	}

	s, err := webhook.NewServer(*port, eventChan, logger.WithName("webhook"))
	if err != nil {
		log.Fatalf("error creating webhook server: %s", err)
	}
	slog.Info("serving", "port", *port)

	var errg errgroup.Group

	errg.Go(func() error {
		return s.ListenAndServe(ctx)
	})
	errg.Go(func() error {
		return mgr.Start(ctx)
	})

	if err := errg.Wait(); err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error(err, "starting webhook and manager")
			os.Exit(1)
		}
		logger.Info("http server closed")
	}
}
