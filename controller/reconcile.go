package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

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
	snykOrgVolume       = "snyk-token"
)

type Reconciler struct {
	Namespace string

	client client.Client
}

func (r *Reconciler) Reconcile(ctx context.Context, req types.RegistryEvent) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithValues("registry", req.Registry, "repository", req.Repository, "digest", req.Digest, "tag", req.Tag)

	labels := labelsForScanJob(req)

	var jobList batchv1.JobList
	err := r.client.List(ctx, &jobList, client.InNamespace(r.Namespace), client.MatchingLabels(labels))
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list existing jobs for scan: %w", err)
	}
	// job for this registry event was previously created, omit
	if len(jobList.Items) > 0 {
		log.Info("Job already present, skipping")
		return reconcile.Result{}, nil
	}

	log.Info("Creating job for webhook event")
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanJobName(req),
			Namespace: r.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					RestartPolicy: v1.RestartPolicyOnFailure,
					Containers: []v1.Container{
						{
							Name:    "scan",
							Image:   "snyk/snyk:linux",
							Command: []string{"snyk"},
							Args:    scanJobArguments(req),
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

func scanJobArguments(e types.RegistryEvent) []string {
	cmd := []string{
		"container",
		"monitor",
		"-d",
		"--org=$(SNYK_ORG)",
	}
	cmd = append(cmd, fmt.Sprintf("--target-reference=%s@%s", e.Tag, e.Digest))
	cmd = append(cmd, e.Reference())
	return cmd
}

func scanJobName(e types.RegistryEvent) string {
	hash := sha256.New()
	hash.Write([]byte(e.Reference()))
	return hex.EncodeToString(hash.Sum(nil))[:63]
}

func labelsForScanJob(e types.RegistryEvent) map[string]string {
	return map[string]string{
		// colon is not allowed in labels, digest uses algo:hash as format
		"digest": strings.ReplaceAll(string(e.Digest), ":", "_")[:63],
		"tag":    e.Tag,
		// colon is not allowed in labels, registry string could contain port
		"registry":   strings.ReplaceAll(e.Registry, ":", "_"),
		"repository": e.Repository,
	}
}