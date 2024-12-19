# Registry Snyk Scan

This project allows you to scan images pushed to your registry with snyk.

## Architecture

The webhook has one POST endpoint `/event` that can be used a **notifications** endpoint for the docker distributions spec.
For an example, see the [ConfigMap in the local setup](deploy/registry.yaml).

The webhook feeds a controller that acts on generic events. The controller is based on [this example](https://github.com/timebertt/controller-runtime/tree/webhook-controller/examples/webhook)

## Local setup

1. Create a kind cluster: `kind create cluster`
2. Create a secret containing your snyk token and organistation:
`kubectl create secret generic --from-literal=SNYK_ORG=XXXX-XXXX-XXXX --from-literal=SNYK_TOKEN=XXXX-XXXX-XXXX snyk-token`

- It is important to name your secret snyk-token

3. Build webhook and deploy dummy registry in the kind cluster: `skaffold dev`
4. Forward the registry to access on your machine: `kubectl port-forward svc/registry 5000:5000`
5. Test the integration by copying images into the dummy registry: `crane copy ubuntu localhost:5000/ubuntu`
