# Collector template

A minimal collector for [vexplain](../../README.md), to copy and make your own. It watches, and sends one piece of
evidence of the type `com.example.hello.v1alpha1`, about a workload: a greeting. It has what every collector has:
settings with a schema, a type with a schema, the conformance test, a Dockerfile and a Makefile.

The guide, [How to write a collector](../../docs/collectors.md), explains the collector API, evidence types,
subjects, coverage, settings, RBAC and conformance, and links to the design for the reasons. Read it next to this
code.

| File | What it is |
|---|---|
| `collector.go` | The collector: what it says about itself (`Info`, `Capabilities`), and its `Watch`. |
| `main.go` | Serves the collector on the ports and with the TLS files that vexplain's deployer sets. |
| `collector_test.go` | Runs the conformance suite of the SDK against the collector, in this process. |
| `Dockerfile` | Builds the image on distroless static, as non-root. |
| `Makefile` | `make test`, `make build`, `make docker-build` and `make docker-push`. |

## Try it

```sh
make test
```

The test serves the collector in this process, without TLS, and runs `conformance.Run` against it. `go test -v`
lists each check, such as `Watch/spoke/reaches SnapshotEnd in time`. Change something that breaks the contract, such
as the type's name in `collector.go` or the data in `Watch`, and watch the check that names it fail.

## Make it yours

1. Copy this directory to a repository of your own.
2. Change the module path in `go.mod`, and the imports with it.
3. **Drop the `replace` line of `go.mod`.** In the vexplain repository it points at the SDK next to the template, so
   that the two are tested together. Your project requires a version of the SDK instead:

   ```sh
   go mod edit -dropreplace github.com/bedag/vexplain/sdk
   go get github.com/bedag/vexplain/sdk@<version>
   go mod tidy
   ```

   The SDK is `v1alpha1`, like the API that it serves: it makes no compatibility promise yet.
4. Name your type in reverse-DNS, with a domain of your own and a version, and describe its data in its schema. Say in
   the schema what each field means, and what the `coverage` of the evidence counts.
5. Change what the collector watches, and the subjects of its evidence. See the guide for the subjects that vexplain
   defines, and for how to add your own.
6. Keep the conformance test, and pass it settings, settings that must be refused, and, when the collector has
   operations, an invocation of each. A collector that produces vexplain's presence type needs a Kubernetes client for
   it: see the guide.

## Build the image

```sh
make docker-build IMG=artifacts.example/collectors/hello:0.1.0 VERSION=0.1.0
```

The build needs the project without the `replace` line, which refers to a directory outside it. The image is
distroless static, and runs as user 65532. vexplain runs it with a read-only root filesystem and no capabilities, so
the collector writes nothing outside the volumes that its runtime config mounts.

`VERSION` is the version that `GetInfo` reports. vexplain stores evidence at it, so a new version replaces what an old
one delivered.

## Install it

A `Collector` installs the image, and installed means enabled:

```yaml
apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: Collector
metadata:
  name: hello
spec:
  package: artifacts.example/collectors/hello:0.1.0
  settings:
    greeting: Hello
```

vexplain then deploys it in its own namespace, with a service account named `vexplain-collector-hello`, and gives it
a server certificate. The collector declares the Kubernetes permissions that it needs in `Capabilities`, and vexplain
grants none: the admin who installs the collector binds them. This one needs none. The guide has the rest.
