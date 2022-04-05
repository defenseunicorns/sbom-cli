# SBOM CLi

Creates an SBOM from a Helm chart assuming it has the following annotations:

```yaml
apiVersion: v2
name: istio
version: 1.11.2-bb.0
annotations:
  helm.sh/cpe: |
    - cpe: cpe:2.3:a:istio:istio:1.11.2:*:*:*:*:*:*:*
  helm.sh/images: |
    - image: registry1.dso.mil/ironbank/opensource/istio/pilot:1.11.2
    - image: registry1.dso.mil/ironbank/opensource/istio/install-cni:1.11.2
    - image: registry1.dso.mil/ironbank/opensource/istio/proxyv2:1.11.2
```

## Running

```bash
go run main.go create --path ../../../packages/istio-controlplane/chart/ --output-file created.xml --output-format cyclonedx
```
