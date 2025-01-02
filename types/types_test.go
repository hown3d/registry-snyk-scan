package types

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"testing"
)

func TestRegistryEvent(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "RegistryEvent Suite")
}

var _ = Describe("RegistryEvent", func() {
	Describe("Reference", func() {
		Context("without digest", func() {
			It("returns the reference in the format 'registry/repository:tag'", func() {
				event := RegistryEvent{
					Registry:   "example.com",
					Repository: "my-app",
					Tag:        "v1.0.0",
					Digest:     "",
				}
				expected := "example.com/my-app:v1.0.0"
				Expect(event.Reference()).To(Equal(expected))
			})
		})

		Context("with digest", func() {
			It("returns the reference in the format 'registry/repository@digest'", func() {
				event := RegistryEvent{
					Registry:   "example.com",
					Repository: "my-app",
					Tag:        "v1.0.0",
					Digest:     "sha256:123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				}
				expected := "example.com/my-app@sha256:123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
				Expect(event.Reference()).To(Equal(expected))
			})
		})
	})
})
