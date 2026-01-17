# cks-prep

get valid spec fields kubernetes via command line for add sys_time capability

```
kubectl explain pod.spec
kubectlkubectl explain pod.spec.containers.securityContext
kubectl explain pod.spec.containers.securityContext.capabilities
kubectl explain pod.spec.containers.securityContext.capabilities.add
```
to remove default annotation from all storage class

```
kubectl annotate storageclass --all storageclass.kubernetes.io/is-default-class-
```
check the process to see enabled and disabled plugins

here ps -ef to get all process in full format with parent processes and everything details there

```
ps -ef | grep kube-apiserver | grep admission-plugins
```

## Kubernetes Mutating and Validating Admission Controllers

Admission controllers are Kubernetes components that **intercept API requests** after authentication and authorization but **before objects are persisted** in etcd.

They are used to **modify**, **validate**, or **reject** Kubernetes objects such as Pods, Deployments, and Services.

### Request Flow in Kubernetes

```text
kubectl / client
        ↓
API Server
  ├─ Authentication
  ├─ Authorization
  ├─ Mutating Admission Controllers
  ├─ Validating Admission Controllers
  └─ Persist object to etcd
```

Mutating Admission Controllers can:
- Modify incoming requests
- Can add, change, or default fields
- Run before validating admission controllers

Common Use Cases
    - Inject sidecars (Istio, Linkerd)
    - Add default labels or annotations
    - Set default resource limits/requests
    - Add tolerations or node selectors
    - Inject security context

Built-in Mutating Controllers
- MutatingAdmissionWebhook
- NamespaceLifecycle
- ServiceAccount
- NodeRestriction

incoming pod
```yaml
spec:
  containers:
  - name: app
    image: nginx 
```
after mutation

```yaml
spec:
  containers:
  - name: app
    image: nginx
    resources:
      limits:
        cpu: "500m"
```
Validating Admission Controllers
- Validate requests only
- Can allow or deny requests
- Cannot modify objects
- Run after mutation
  Common Use Cases
  - Enforce security policies
  - Block privileged containers
  - Require labels or annotations
  - Enforce naming conventions
  - Prevent dangerous configurations

Built-in Validating Controllers
- ValidatingAdmissionWebhook
- PodSecurity
- ResourceQuota
- LimitRanger
Example (Validation Rule)
Deny Pods that run as root or add forbidden Linux capabilities

Enabled via kube-apiserver flags:
```bash
--enable-admission-plugins=PodSecurity,MutatingAdmissionWebhook
```

to get namespace labels:
```bash
kubectl get namespace <namespace> --show-labels
```
## OPA
to download binaries for opa always use -L with curl , -L follows redirect wince actual binaries exist at
redirect storage page objects.githubusercontent.com , without this we will not get binary but only html
```
curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/v0.38.1/opa_linux_amd64
chmod 755 ./opa
./opa run -s &

```

to test policy file with opa
```
./opa test example.rego
```

to load policy file in opa. here note --data-binary is necessary, We use PUT with --data-binary because OPA’s policy API is idempotent and resource-based, and POST is not supported for uploading policies.
```
curl -X PUT --data-binary @sample.rego http://localhost:8181/v1/policies/samplepolicy
```
## OPA Gatekeeper
OPA Gatekeeper is a policy enforcement tool for Kubernetes that helps you define, enforce, and audit rules about how your clusters are used
Gatekeeper lets you say “what is allowed and what is not” in Kubernetes — and enforces it automatically.

Gatekeeper workflow:
- User applies a manifest (kubectl apply)
- Kubernetes API Server calls Gatekeeper (admission webhook)
- Gatekeeper evaluates policies (Rego)
- Request is allowed or denied
- Violations are recorded for auditing

🧩 Key Components

1️⃣ ConstraintTemplate
Defines what a policy checks (written in Rego).
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg}] {
          missing := input.parameters.labels[_]
          not input.review.object.metadata.labels[missing]
          msg := sprintf("Missing label: %v", [missing])
        }
```
2️⃣ Constraint
Defines where and how the policy applies.
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    labels: ["owner", "environment"]
```
3️⃣ Audit
Gatekeeper periodically scans existing resources and reports violations:
```bash
kubectl get constraintviolations
```
## secret
secret object can be created
```
kubectl create secret generic test --from-literal=host=db_host --from-literal=password=hello
```
this secret can then be used in pod via envFrom and secretRef fields in pod spec section as follows:

```yaml
spec:
  containers:
    envFrom:
      - secretRef:
          name: test
```

## RuntimeClass:
 to get the information of current runtime used
 ```bash
kubectl get nodes -o wide
```
this command will show containerd or anything else, then to know runtime
we can check either /etc/containerd/config.toml to know the runtime
or use the command:
```bash
ps -aux|grep runc
```
to get no of runtimeclass already present in environment
```bash
kubectl get runtimeclasses
kubectl get rc
```
to get the api group of runtimeclass:
```bash
kubectl api-resources | grep RuntimeClass
```
create runtime class via yaml 
```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```
to use this in pod
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  runtimeClassName: gvisor
  containers:
    - name: app
      image: nginx
```
## resourcequotas
```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-resources
spec:
  hard:
    requests.cpu: "1"
    requests.memory: "1Gi"
    limits.cpu: "2"
    limits.memory: "2Gi"
    requests.nvidia.com/gpu
```
kubernetes network policy work on above data link layer for pod to pod communication in osi model.
that is network layer.

## Taints and Toleration
to taint node in kubernetes
```bash
kubectl taint node node03 team=team-c:NoSchedule
```
to apply toleration on pod for taint here is the yaml

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: team-a-pod
  name: team-a-pod
  namespace: team-a

spec:
  tolerations:
  - effect: NoSchedule
    key: team
    operator: Equal
    value: team-a
  containers:
  - image: nginx
    name: team-a-pod
    resources: {}
  dnsPolicy: ClusterFirst
  restartPolicy: Always
status: {}
```
to remove taint from node:
```bash
kubectl taint node node03 team=team-c:NoSchedule-
```
## Istio
to check if istio enabled ns exist. note namespace should be injected with istio here.
```bash
kubectl get ns --show-labels
```
> https://istio.io/latest/docs/reference/config/security/peer_authentication/
```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: foo ## for global policy set namespace to namespace: istio-system
spec:
  mtls:
    mode: STRICT
```
to enable istion injection to test namespace
```bash
kubectl label ns test istio-injection=enabled
```

to create specific namespace level permissive mode peer authntication policy
```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: foo
spec:
  mtls:
    mode: PERMISSIVE

```
to create permissive policy for specific app
```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: finance
  namespace: foo
spec:
  selector:
    matchLabels:
      app: finance
  mtls:
    mode: STRICT
```
## cilium
[cilium documentation](https://docs.cilium.io/en/stable/security/network/encryption/)
```
cilium install --version 1.18.5
cilium status --wait
cilium connectivity test
```
to install cilium along with wirecard encryption enabled is:
```
cilium install --version 1.18.5    --set encryption.enabled=true    --set encryption.type=wireguard
```
to install it via helm
```
# Install Cilium with encryption enabled
helm install cilium cilium/cilium --version v1.18.0-pre.0 \
  --namespace kube-system \
  --set encryption.enabled=true \
  --set encryption.type=wireguard
```
to check clium status
```
cilium status
```
for cilium encryption status
```
cilium encryption status
```
create a curl pod with command cleep 3600
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    app: curlpod
  name: curlpod
spec:
  containers:
  - image: rapidfort/curl
    name: curlpod
    command: ["sleep"]
    args: ["3600"]
    resources: {}
  dnsPolicy: ClusterFirst
  restartPolicy: Always
status: {}
```

Check connectivity between the pods, in a new terminal window run the following command:
```
watch kubectl exec -it curlpod -- curl -s http://nginx

```
Run a bash shell in one of the Cilium pods with
```
kubectl -n kube-system exec -ti ds/cilium -- bash
```
Check that WireGuard has been enabled (number of peers should correspond to a number of nodes subtracted by one)
```
cilium-dbg status | grep Encryption
```
Install tcpdump
```
apt-get update
apt-get -y install tcpdump
```
Check that traffic is sent via the cilium_wg0 tunnel device is encrypted:
```
tcpdump -n -i cilium_wg0 -X
```
Here we are using `tcpdump`` to capture and display detailed network packets on the cilium_wg0 interface.

The -n option avoids DNS lookups, and the -X option shows packet content in both hexadecimal and ASCII format.

Via tcpdump, you should see the traffic between the pods.

We see requests from curlpod to nginx and responses from nginx to curlpod in tcpdump output.

## creating and analyzing sboms:
- Syft: A CLI tool and Go library for generating a Software Bill of Materials (SBOM) from container images and filesystems. Exceptional for vulnerability detection when used with a scanner like Grype.
  installation of syft:
  ```bash
  curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
  ```
- Grype:A vulnerability scanner for container images and filesystems.
  installation of grype:
  ```bash
  curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
  ```
  > reference:
     1. https://github.com/anchore/syft
     2. https://github.com/anchore/grype

to read grype reports we can use jq filters as follows:
```bash
cat grype-report.json | jq '.matches[]|select(.vulnerability.id=="CVE-2018-1000517")|.vulnerability.description'
```

  




