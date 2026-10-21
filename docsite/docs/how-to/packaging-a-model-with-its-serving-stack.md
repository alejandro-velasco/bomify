---
icon: lucide/brain
---

# Packaging a model with its serving stack

A model rarely ships alone: it runs in a serving runtime, which a Helm
chart deploys. Packaging all three as one bomify package versions,
signs, scans, and moves them together. Push then tags each piece where
its own tool pulls it.

A model published as an OCI artifact is a `pkg:oci` component, kept as
it is:

| Format | Published by | Pulled by |
| --- | --- | --- |
| [ModelPack](https://github.com/modelpack/model-spec) | `modctl`, Docker Hub's `ai/*:*-safetensors` models | `modctl` |
| [KitOps](https://kitops.org) ModelKit | `kit` | `kit` |
| Docker Model Runner | `docker model`, Docker Hub's `ai/*` GGUF models | `docker model` |

A model on the Hugging Face Hub can instead be a `pkg:huggingface`
component, which push publishes as ModelPack (see
[bomify-plugin-huggingface](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-huggingface)).

This guide packages [vLLM](https://docs.vllm.ai)'s
[production stack](https://github.com/vllm-project/production-stack)
chart, the images it runs, and a small model, Docker Hub's ModelPack
copy of SmolLM2. It needs the `helm` and `oci` plugins.

## 1. Compose the stack

Pin the images the chart runs, in its values:

```yaml
# values.yaml
servingEngineSpec:
  modelSpec:
  - name: smollm2
    repository: vllm/vllm-openai
    tag: v0.32.0
    modelURL: HuggingFaceTB/SmolLM2-135M
    replicaCount: 1
    requestCPU: 2
    requestMemory: 4Gi
    requestGPU: 1
routerSpec:
  tag: v0.1.13
```

Then compose the chart, and every image it renders, with the model:

```yaml
# bomify.yaml
name: llm-serving
version: 1.0.0
sources:
  - name: stack
    medium: helm
    options:
      chart: vllm-stack
      repo: https://vllm-project.github.io/production-stack
      version: 0.1.13
      values:
        - values.yaml
components:
  - type: machine-learning-model
    name: smollm2
    version: 135m-safetensors
    purl: pkg:oci/smollm2@135m-safetensors?repository_url=docker.io/ai/smollm2
```

```sh
bomify sbom compose bomify.yaml -o llm-serving.cdx.json
```

The SBOM lists four components: the chart, the vLLM engine and router
images it renders, and the model. It's
[`testdata/llm-serving.cdx.json`](https://github.com/alejandro-velasco/bomify/blob/main/testdata/llm-serving.cdx.json).
See [composing a multi-medium package](composing-a-multi-medium-package.md)
for the composition file's options.

## 2. Build and push

```sh
bomify build llm-serving.cdx.json --tag registry.example.com/team/llm-serving:1.0.0
bomify push registry.example.com/team/llm-serving:1.0.0
```

The vLLM image is about 9 GB, which `build` pulls once and `push`
uploads once; a later version uploads only what changed. Add `--sign`
to sign the package and each piece where it's tagged (see
[signing and verifying packages](signing-and-verifying-packages.md)).

## 3. Pull each piece with its own tool

Each component is tagged beside the package, as the same manifest the
package holds, so the model keeps the digest Docker Hub gave it:

```sh
helm pull oci://registry.example.com/team/llm-serving/helm/vllm-stack --version 0.1.13
docker pull registry.example.com/team/llm-serving/oci/vllm-openai:v0.32.0
modctl pull registry.example.com/team/llm-serving/oci/smollm2:135m-safetensors
modctl extract registry.example.com/team/llm-serving/oci/smollm2:135m-safetensors --output ./smollm2
```

A ModelKit is pulled with `kit pull` and `kit unpack` the same way. Or
restore the whole package, model included, with
`bomify pull registry.example.com/team/llm-serving:1.0.0`.

## 4. Install the chart from the package

Point the chart's images at their copies in the package:

```sh
helm install llm oci://registry.example.com/team/llm-serving/helm/vllm-stack --version 0.1.13 \
  -f values.yaml \
  --set servingEngineSpec.modelSpec[0].repository=registry.example.com/team/llm-serving/oci/vllm-openai \
  --set routerSpec.repository=registry.example.com/team/llm-serving/oci/lmstack-router
```

As written, vLLM downloads the model named by `modelURL` from the
Hugging Face Hub. To serve the packaged copy instead, get its files into
the engine's pod, for example with an init container that runs `modctl
extract` into a volume the engine mounts, and set `modelURL` to their
path. The chart's `initContainer`, `extraVolumes`, and
`extraVolumeMounts` values are where that goes.
