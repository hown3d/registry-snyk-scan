package controller

import (
	"context"

	"github.com/stackitcloud/registry-snyk-scan/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// ControllerName is the name of the controller.
const ControllerName = "job-creator"

// AddToManager adds Reconciler to the given manager.
func (r *Reconciler) AddToManager(mgr manager.Manager, sourceChannel <-chan event.TypedGenericEvent[types.RegistryEvent]) error {
	if r.client == nil {
		r.client = mgr.GetClient()
	}

	return builder.TypedControllerManagedBy[types.RegistryEvent](mgr).
		Named(ControllerName).
		WatchesRawSource(source.TypedChannel[types.RegistryEvent, types.RegistryEvent](sourceChannel, &handler.TypedFuncs[types.RegistryEvent, types.RegistryEvent]{
			GenericFunc: func(ctx context.Context, e event.TypedGenericEvent[types.RegistryEvent], w workqueue.TypedRateLimitingInterface[types.RegistryEvent]) {
				w.Add(e.Object)
			},
		})).
		Complete(r)
}
