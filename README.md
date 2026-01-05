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


