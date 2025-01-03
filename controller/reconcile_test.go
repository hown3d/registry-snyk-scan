package controller

import (
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	registryfake "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	imagev1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stackitcloud/registry-snyk-scan/types"
	batchv1 "k8s.io/api/batch/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Reconcile", func() {
	// override RemoteImage function in types package to ensure that we don't actually call the registry
	originalRemoteImage := types.RemoteImage
	BeforeEach(func() {
		types.RemoteImage = func(ref name.Reference, options ...remote.Option) (v1.Image, error) {
			return &registryfake.FakeImage{
				ConfigFileStub: func() (*v1.ConfigFile, error) {
					return &v1.ConfigFile{
						Architecture: "amd64",
						OS:           "linux",
					}, nil
				},
			}, nil
		}
		DeferCleanup(func() {
			types.RemoteImage = originalRemoteImage
		})
	})

	It("should create a job if it does not exist already", func(ctx SpecContext) {
		client := fake.NewClientBuilder().Build()

		r := Reconciler{
			client: client,
		}

		req := types.RegistryEvent{
			Registry:   "docker.io",
			Repository: "library/ubuntu",
			Tag:        "latest",
			Digest:     "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
		}
		jobName := scanJobName(req)

		_, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		var jobs batchv1.JobList
		err = client.List(ctx, &jobs)
		Expect(err).NotTo(HaveOccurred())
		Expect(jobs.Items).To(HaveLen(1))
		Expect(jobs.Items[0].Name).To(Equal(jobName))
	})

	It("should skip creating job if already exists", func(ctx SpecContext) {
		req := types.RegistryEvent{
			Registry:   "docker.io",
			Repository: "library/ubuntu",
			Tag:        "latest",
			Digest:     "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
		}
		jobName := scanJobName(req)
		job := batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name: jobName,
			},
		}
		client := fake.NewClientBuilder().
			WithObjects(&job).
			Build()

		r := Reconciler{
			client: client,
		}

		_, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		var newjob batchv1.Job
		err = client.Get(ctx, k8stypes.NamespacedName{
			Name: jobName,
		}, &newjob)
		Expect(err).NotTo(HaveOccurred())
		// check that job did not change during reconcilation
		Expect(job).To(Equal(newjob))
	})
})

var _ = DescribeTable("isPlatformSupported", func(platform imagev1.Platform, expected bool) {
	Expect(isPlatformSupported(platform)).To((Equal(expected)))
},
	Entry("supported should return true", imagev1.Platform{OS: "linux", Architecture: "amd64"}, true),
	Entry("windows platform should return false", imagev1.Platform{OS: "windows"}, false),
)
