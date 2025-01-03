package controller

import imagev1 "github.com/opencontainers/image-spec/specs-go/v1"

const (
	snykTokenSecretName = "snyk-token"
)

var supportedPlatforms = []imagev1.Platform{
	{
		OS:           "linux",
		Architecture: "amd64",
	},
	{
		OS:           "linux",
		Architecture: "riscv64",
	},
	{
		OS:           "linux",
		Architecture: "ppc64le",
	},
	{
		OS:           "linux",
		Architecture: "s390x",
	},
	{
		OS:           "linux",
		Architecture: "386",
	},
	{
		OS:           "linux",
		Architecture: "arm64",
	},
	{
		OS:           "linux",
		Architecture: "arm",
		Variant:      "v7",
	},
	{
		OS:           "linux",
		Architecture: "arm",
		Variant:      "v6",
	},
}
