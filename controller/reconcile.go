package controller

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/stackitcloud/registry-snyk-scan/types"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	snykTokenSecretName = "snyk-token"
	snykTokenVolume     = "snyk-token"
)

type Reconciler struct {
	client client.Client
}

func (r *Reconciler) Reconcile(ctx context.Context, req types.RegistryEvent) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithValues("registry", req.Registry, "repository", req.Repository, "digest", req.Digest, "tag", req.Tag, "platform/os", req.Platform.OS, "platform/arch", req.Platform.Architecture)
	log.Info("Creating job for webhook event")

	labels := labelsForScanJob(req)

	var jobList batchv1.JobList
	err := r.client.List(ctx, &jobList, client.MatchingLabels(labels))
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list existing jobs for scan: %w", err)
	}
	// job for this registry event was previously created, omit
	if len(jobList.Items) > 0 {
		return reconcile.Result{}, nil
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:   scanJobName(req),
			Labels: labels,
		},
		Spec: batchv1.JobSpec{
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:    "scan",
							Image:   "snyk/snyk:linux",
							Command: scanJobCommand(req),
							Env: []v1.EnvVar{
								{
									Name: "SNYK_TOKEN",
									ValueFrom: &v1.EnvVarSource{
										SecretKeyRef: &v1.SecretKeySelector{
											Key: "SNYK_TOKEN",
											LocalObjectReference: v1.LocalObjectReference{
												Name: snykTokenSecretName,
											},
										},
									},
								},
								{
									Name: "SNYK_ORG",
									ValueFrom: &v1.EnvVarSource{
										SecretKeyRef: &v1.SecretKeySelector{
											Key: "SNYK_ORG",
											LocalObjectReference: v1.LocalObjectReference{
												Name: snykTokenSecretName,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if err := r.client.Create(ctx, job); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to create job: %w", err)
	}

	return reconcile.Result{}, nil
}

func scanJobCommand(e types.RegistryEvent) []string {
	cmd := []string{
		"snyk",
		"container",
		"monitor",
		"--org=${SNYK_ORG}",
	}
	cmd = append(cmd, "--platform", fmt.Sprintf("%s/%s", e.Platform.OS, e.Platform.Architecture))
	cmd = append(cmd, "--target-reference", fmt.Sprintf("%s@%s", e.Tag, e.Digest))
	cmd = append(cmd, e.Reference())
	return cmd
}

func scanJobName(e types.RegistryEvent) string {
	hash := sha256.New()
	s := fmt.Sprintf("%s/%s:%s@%s-%s/%s", e.Registry, e.Repository, e.Tag, e.Digest, e.Platform.OS, e.Platform.Architecture)
	return string(hash.Sum([]byte(s)))
}

func labelsForScanJob(e types.RegistryEvent) map[string]string {
	return map[string]string{
		"digest":     string(e.Digest),
		"tag":        e.Tag,
		"registry":   e.Registry,
		"repository": e.Repository,
		"platform":   fmt.Sprintf("%s/%s", e.Platform.OS, e.Platform.Architecture),
	}
}
