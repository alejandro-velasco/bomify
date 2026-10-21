---
icon: lucide/brain
---

# Packaging a model with its serving stack

A model rarely ships alone: it runs in a serving runtime, which a Helm
chart deploys. Packaging all three as one bomify package versions,
signs, scans, and moves them together. Push then tags each piece where
its own tool pulls it, and the chart can serve the model straight from
the package.

A model is a component in either of two ways:

- **From the Hugging Face Hub**, as a `pkg:huggingface` component, which
  push publishes as a [ModelPack](https://github.com/modelpack/model-spec)
  artifact, each file a layer titled with its path (see
  [bomify-plugin-huggingface](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-huggingface)).
- **Already published as an OCI artifact**, as a `pkg:oci` component,
  kept as it is:

    | Format | Published by | Pulled by |
    | --- | --- | --- |
    | ModelPack | `modctl`, Docker Hub's `ai/*:*-safetensors` models | `modctl` |
    | [KitOps](https://kitops.org) ModelKit | `kit` | `kit` |
    | Docker Model Runner | `docker model`, Docker Hub's `ai/*` GGUF models | `docker model` |

This guide packages [vLLM](https://docs.vllm.ai)'s
[production stack](https://github.com/vllm-project/production-stack)
chart, the images it runs, and a small model from the Hub,
[SmolLM2-135M](https://huggingface.co/HuggingFaceTB/SmolLM2-135M), then
serves the model from the package. It needs the `helm`, `oci`, and
`huggingface` plugins.

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
routerSpec:
  tag: v0.1.13
```

Then compose the chart, and every image it renders, with the model,
pinned to a commit:

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
    name: SmolLM2-135M
    version: 93efa2f097d58c2a74874c7e644dbc9b0cee75a2
    purl: pkg:huggingface/HuggingFaceTB/SmolLM2-135M@93efa2f097d58c2a74874c7e644dbc9b0cee75a2
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
package holds. A repository path is lowercase, so the model's is
`huggingface/huggingfacetb/smollm2-135m`:

```sh
helm pull oci://registry.example.com/team/llm-serving/helm/vllm-stack --version 0.1.13
docker pull registry.example.com/team/llm-serving/oci/vllm-openai:v0.32.0
oras pull registry.example.com/team/llm-serving/huggingface/huggingfacetb/smollm2-135m:93efa2f097d58c2a74874c7e644dbc9b0cee75a2 \
  --output ./smollm2
```

`oras pull` writes the model's files out as they are on the Hub, as does
`modctl extract`. Or restore the whole package with
`bomify pull registry.example.com/team/llm-serving:1.0.0`.

## 4. Serve the model from the package

vLLM serves whatever `modelURL` names, a Hub ID or a local directory.
To serve the packaged model, the chart's init container pulls it with
`oras` into the model's volume, mounted at `/data`, and `modelURL`
names it there. The images come from the package too:

```yaml
# serve.yaml
servingEngineSpec:
  modelSpec:
  - name: smollm2
    repository: registry.example.com/team/llm-serving/oci/vllm-openai
    tag: v0.32.0
    modelURL: /data/smollm2
    replicaCount: 1
    requestCPU: 2
    requestMemory: 4Gi
    requestGPU: 1
    pvcStorage: 2Gi
    shmSize: 1Gi
    vllmConfig:
      tensorParallelSize: 1
    extraVolumes:
    - name: registry-auth
      secret:
        secretName: registry-auth
    initContainer:
      name: fetch-model
      image: ghcr.io/oras-project/oras:v1.3.5
      args:
      - pull
      - registry.example.com/team/llm-serving/huggingface/huggingfacetb/smollm2-135m:93efa2f097d58c2a74874c7e644dbc9b0cee75a2
      - --output
      - /data/smollm2
      - --registry-config
      - /auth/.dockerconfigjson
      mountPvcStorage: true
      extraVolumeMounts:
      - name: registry-auth
        mountPath: /auth
routerSpec:
  repository: registry.example.com/team/llm-serving/oci/lmstack-router
  tag: v0.1.13
```

- `vllmConfig.tensorParallelSize` is what makes the chart mount
  `/dev/shm` at `shmSize`; without it, vLLM fails to start for lack of
  shared memory.
- `registry-auth` holds the registry's credentials, for the init
  container's `oras`:

    ```sh
    kubectl create secret docker-registry registry-auth --docker-server=registry.example.com \
      --docker-username=<user> --docker-password=<token>
    ```

```sh
helm install llm oci://registry.example.com/team/llm-serving/helm/vllm-stack --version 0.1.13 -f serve.yaml
```

vLLM's OpenAI-compatible API serves the model under its path,
`/data/smollm2`, on the engine's service, `<release>-<model>-engine-service`.
SmolLM2-135M is a base model, without a chat template, so ask it for a
completion:

```sh
kubectl port-forward svc/llm-smollm2-engine-service 8000:80
curl -s localhost:8000/v1/completions -H 'Content-Type: application/json' \
  -d '{"model": "/data/smollm2", "prompt": "The capital of France is", "max_tokens": 20}'
```

On a cluster without GPUs, run vLLM's CPU build,
`vllm/vllm-openai-cpu`, with `requestGPU: 0`, `runtimeClassName: ""`,
and `vllmConfig.gpuMemoryUtilization` low enough to leave the node room:
on the CPU backend it's the fraction of the node's memory vLLM reserves.

Two ways that don't work:

- **A Kubernetes image volume** of the model's repository: containerd
  mounts a ModelPack artifact's layers, which are files rather than
  tars, as an empty directory.
- **`oras pull` of a model without titled layers**, such as Docker Hub's
  ModelPack models, which name each file in `org.cncf.model.filepath`
  alone: `oras` writes nothing. Pull those with `modctl extract`
  instead.
