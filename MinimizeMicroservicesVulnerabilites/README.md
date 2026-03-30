# Minimize Microservices Vulnerabilities

## SecurityContext

- What is the user used to execute the sleep process within the ubuntu-sleeper pod?

```
   kubectl exec ubuntu-sleeper -- whoami
```

- Edit the pod ubuntu-sleeper running in the default namespace, to run the sleep process with user ID 1010.

```yaml
  securityContext:      # Update securityContext
    runAsUser: 1010
```

- when multiple secuity context is there at pod and container level.

```
  The User ID defined in the securityContext of the container overrides the User ID in the POD.
```

- Update the pod ubuntu-sleeper to run as Root user and with the SYS_TIME capability.

```yaml
 securityContext:        # Updated securityContext on container level
      capabilities:
        add: ["SYS_TIME"]
```

- Now update the pod to also make use of the NET_ADMIN capability.

```yaml
 securityContext:        # Updated securityContext on container level
      capabilities:
        add: ["SYS_TIME", "NET_ADMIN"]
```

## AdmissionControllers
- Reconfigure the ImagePolicyWebhook to reject images when the webhook backend is unavailable (fail-closed).

```
vi /etc/kubernetes/imgvalidation/imagepolicy-conf.yamlvi /etc/kubernetes/imgvalidation/imagepolicy-conf.yaml

imagePolicy:
  kubeConfigFile: /etc/kubernetes/imgvalidation/kubeconf.yaml
  allowTTL: 50
  denyTTL: 50
  retryBackoff: 500
  defaultAllow: false
```
note: Setting defaultAllow: false enforces a fail-closed policy — if the webhook backend is unavailable, all image pull requests will be denied. This is the recommended security posture for production environments.

- Next

6 / 8
The kubeconfig file at /etc/kubernetes/imgvalidation/kubeconf.yaml is missing the correct webhook server endpoint.

Update the server field under clusters[0].cluster to point to the image scanner webhook:

https://image-checker-webhook.default.svc:1323/image_policy


Note: The kubeconfig file is used by the API server to communicate with the external image policy webhook. The server field must contain the full URL of the webhook endpoint

```
vi /etc/kubernetes/imgvalidation/kubeconf.yaml
update server to img server url: https://image-checker-webhook.default.svc:1323/image_policy
```
- Reconfigure the API server to enable the ImagePolicyWebhook admission plugin and ensure it can access the configuration files.

Edit /etc/kubernetes/manifests/kube-apiserver.yaml:

```
cp /etc/kubernetes/manifests/kube-apiserver.yaml /opt/kube-apiserver.yaml.bak
vi /etc/kubernetes/manifests/kube-apiserver.yaml
```
1. Enable the admission plugin:
```
    - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
```
2. Add the admission control config file:
```
    - --admission-control-config-file=/etc/kubernetes/imgvalidation/admission-configuration.yaml
```
3. Mount the imgvalidation directory:
```
Add to volumes:

    - name: imgvalidation
      hostPath:
        path: /etc/kubernetes/imgvalidation
        type: Directory
Add to volumeMounts:

    - name: imgvalidation
      mountPath: /etc/kubernetes/imgvalidation
      readOnly: true
```
4. Verify the API server is running:
```
kubectl get pods -n kube-system
```
## Validating and Mutating Admission Controllers
- namespace exists - validatíng admission controller
- namespaceautoprovision - mutating admission controller
- flow of invocation of admission controllers?
  In Kubernetes, admission controllers are plugins that intercept requests to the API server before they are persisted. They help enforce policies or modify requests.

The flow of invocation is:

Mutating admission controllers: They can modify the incoming request (like adding labels or changing configurations).
Validating admission controllers: They check if the request complies with policies without modifying it.
So, the correct flow is: First Mutating, then Validating. This order ensures that any necessary modifications are made before validation checks are performed.

- Create a TLS secret named webhook-server-tls in the webhook-demo namespace.

This secret will be used by the admission webhook server for secure communication over HTTPS.


We have already created below cert and key for webhook server which should be used to create secret.

Certificate : /root/keys/webhook-server-tls.crt

Key : /root/keys/webhook-server-tls.key

```
k create secret tls webhook-server-tls --cert=/root/keys/webhook-server-tls.crt --key=/root/keys/webhook-server-tls.key -n webhook-demo
```

## Pod Security Admission

- By default, PodSecurity admission is enabled in your cluster. To verify this configuration, you can use the following command:
```
  kubectl exec -n kube-system kube-apiserver-controlplane \
-- kube-apiserver -h | grep enable-admission
```

- We want to apply pod security on namespace alpha. To achieve that, add the following label to the namespace alpha .
```
pod-security.kubernetes.io/warn=baseline
```
```
k label ns alpha pod-security.kubernetes.io/warn=baseline
```

- ```
cat baseline-pod.yaml 
apiVersion: v1
kind: Pod
metadata:
  name: baseline-pod
  namespace: alpha
spec:
  containers:
  - image: nginx
    name: baseline-pod
    securityContext:
       privileged: true
```
- While applying the manifest baseline-pod.yaml in the preceding question, you would have encountered a warning message that stated:

Warning: would violate PodSecurity "baseline:latest": 
privileged (container "baseline-pod" must not set securityContext.privileged=true)

In the previous task, the label pod-security.kubernetes.io/warn=baseline was applied to the namespace alpha. Within the pod definition file, the securityContext.privileged=true was specified. Therefore, since the Baseline level does not permit privileged containers, a warning was generated.

For more information on the various levels of Pod Security, you can refer to the Kubernetes documentation on Pod Security Standards, bookmarked as PSP Documentation above the terminal pane.

- We can also use multiple pod security standards together for a single namespace.

For this step, label the namespace beta with the enforce mode and baseline level, as well as the warn mode and the restricted level.

```
kubectl label ns beta \
pod-security.kubernetes.io/enforce=baseline \
pod-security.kubernetes.io/warn=restricted
```
- We have provided a manifest multi-psa.yaml at the /root location of the lab terminal.

Inspect it and create the pod using the manifest in the beta namespace.


Note: You might see some warnings while applying manifest. It is expected.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: multi-psa
  namespace: beta
spec:
  containers:
  - name: multi-psa
    image: nginx
    securityContext:
      runAsUser: 0
```
```bash
kubectl apply -f /root/multi-psa.yaml 
```
- While applying the manifest multi-psa.yaml in the previous question, you would have seen a warning message as follows:

Warning: would violate PodSecurity "restricted:latest": allowPrivilegeEscalation != false (container "multi-psa" must set securityContext.allowPrivilegeEscalation=false), 
unrestricted capabilities (container "multi-psa" must set securityContext.capabilities.drop=["ALL"]), runAsNonRoot != true (pod or container "multi-psa" must set securityContext.runAsNonRoot=true), 
runAsUser=0 (container "multi-psa" must not set runAsUser=0), seccompProfile (pod or container "multi-psa" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")

Pod will be created as it does not violate the baseline security standard but it does violate the restricted standard.

Also, it will be created despite violating the restricted standard because the restricted standard is in warn mode. In this mode, although the pod does not adhere to the restricted standard, it is allowed to be created, and a warning message is issued during the pod creation process.

- if following is the yaml admission-configuration file
```yaml
kind: AdmissionConfiguration
plugins:
  - name: PodSecurity
    configuration:
      apiVersion: pod-security.admission.config.k8s.io/v1
      kind: PodSecurityConfiguration
      defaults:
        enforce: baseline
        enforce-version: latest
        audit: restricted
        audit-version: latest
        warn: restricted
        warn-version: latest
      exemptions:
        usernames: [] 
        runtimeClassNames: [] 
        namespaces: [my-namespace]  
```

then enforced: bseline and restricted is auditing and warning

## OPA

- OPA stands for Open Policy Agent
- to download and install opa
```
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod 755 ./opa
opa version
```
- to run opa
```
./opa run -s &
```
- default port on which opa runs is 8181
- rego language is used to write opa policies
- to test a policy in opa 
```
./opa test example.rego
```

- to load a policy in opa
```
curl -X PUT --data-binary @file.rego http://localhost:8181/v1/policies/policyname
```