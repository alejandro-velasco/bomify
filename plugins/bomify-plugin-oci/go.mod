module github.com/alejandro-velasco/bomify/plugins/bomify-plugin-oci

go 1.27.0

replace github.com/alejandro-velasco/bomify => ../..

require (
	github.com/CycloneDX/cyclonedx-go v0.12.0
	github.com/alejandro-velasco/bomify v0.0.0-00010101000000-000000000000
	github.com/google/go-containerregistry v0.22.1
	github.com/opencontainers/image-spec v1.1.1
	github.com/package-url/packageurl-go v0.1.7
	github.com/spf13/cobra v1.10.2
)

require (
	github.com/docker/cli v29.7.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.5 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/lmittmann/tint v1.2.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	oras.land/oras-go/v2 v2.6.2 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)
