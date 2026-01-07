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

