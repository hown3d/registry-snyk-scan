package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	imagev1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stackitcloud/registry-snyk-scan/types"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type Reconciler struct {
	Namespace        string
	InsecureRegistry bool

	client client.Client
}

func (r *Reconciler) Reconcile(ctx context.Context, req types.RegistryEvent) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithValues("registry", req.Registry, "repository", req.Repository, "digest", req.Digest, "tag", req.Tag)

	platform, err := req.Platform(r.InsecureRegistry)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get platform for registry event: %w", err)
	}

	if !isPlatformSupported(platform) {
		log.Info("skipping unsupported platform", "platform", platform)
		return reconcile.Result{}, nil
	}

	log.Info("Creating job for webhook event")
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanJobName(req),
			Namespace: r.Namespace,
			Labels:    labelsForScanJob(req),
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
							Args:    scanJobArguments(req, platform, r.InsecureRegistry),
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
								{
									Name:  "SNYK_DISABLE_ANALYTICS",
									Value: "1",
								},
							},
						},
					},
				},
			},
		},
	}

	if err := r.client.Create(ctx, job); err != nil {
		// skip already existing jobs
		if apierrors.IsAlreadyExists(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("failed to create job: %w", err)
	}

	return reconcile.Result{}, nil
}

func isPlatformSupported(platform imagev1.Platform) bool {
	return slices.ContainsFunc(supportedPlatforms, func(p imagev1.Platform) bool {
		return p.Architecture == platform.Architecture &&
			p.OS == platform.OS
	})
}

func scanJobArguments(e types.RegistryEvent, p imagev1.Platform, insecureRegistry bool) []string {
	cmd := []string{
		"container",
		"monitor",
		"-d",
		"--org=$(SNYK_ORG)",
	}
	if insecureRegistry {
		cmd = append(cmd, "--insecure")
	}
	cmd = append(cmd, fmt.Sprintf("--target-reference=%s@%s", e.Tag, e.Digest))
	cmd = append(cmd, fmt.Sprintf("--platform=%s/%s", p.OS, p.Architecture))
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
