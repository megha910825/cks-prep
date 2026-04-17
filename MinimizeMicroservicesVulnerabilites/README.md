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

## kube-mgmt

- What needs to be done to enable kube-mgmt to automatically identify policies defined in kubernetes and load them into OPA?

  create configmaps in kubernetes with label opa
- create configmap with file as follows:
```
k create cm untrusted-registry --from-file=untrusted-registry.rego
```
## OPA Gatekeeper

- deploy gatekeeper as follows:
```
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.22.0/deploy/gatekeeper.yaml
```
- Create a pod alpha in namespace engineering with label tech: web using nginx image

```
k run alpha -n engineering --image=nginx -l=tech=web
```

- sample constraint template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels

        violation[{"msg": msg, "details": {"missing_labels": missing}}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("you must provide labels: %v", [missing])
        }
```
- sample constraint
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: require-tech-label
spec:
  match:
    namespaces: ["engineering"]
  parameters:
    labels: ["tech"]
```
To create ConstraintTemplate k8sreplicalimits, use the provided manifest.
kubectl apply -f k8sreplicalimits.yaml
Once, the template is created, create a Constraint k8sreplicalimits that will use the ConstraintTemplate k8sreplicalimits. You can use the following manifest to enforce the replica limits.
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sReplicaLimits
metadata:
  name: replica-limits
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
  parameters:
    ranges:
    - min_replicas: 2
      max_replicas: 5

## Manage Kubernetes secret
- create generic secret
  ```
  k create secret generic db-secret --from-literal=DB_Host=sql01 --from-literal=DB_User=root --from-literal=DB_Password=password123
  ```
- Configure the webapp-pod to load environment variables from the db-secret secret you created in the previous task.


Note:

Use envFrom with secretRef to load ALL secret keys as environment variables
The pod must be deleted and recreated (environment variables cannot be updated on running pods)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: webapp-pod
  labels:
    name: webapp-pod
  namespace: default
spec:
  containers:
  - name: webapp
    image: kodekloud/simple-webapp-mysql
    imagePullPolicy: Always
    envFrom:
    - secretRef:
        name: db-secret
```

## Using Runtimes in Kubernetes
- Which is the default runtime used by this cluster?

   First inspect the runtime used by the kubernetes cluster.
   to get the runtime of kubernetes cluster:
   ```
   k get nodes -o wide
   crictl ps
   crictl inspect --output json 956dbb686804d | grep runtime
   ```
- to get the information of different runtimeclases
  ```
  k get runtimeclasses
  ```
- What is the handler used by the runtime class called gvisor?
  ```
    k describe runtimeclass gvisor
  ```
- Create a new runtime class called secure-runtime with the following specs:


Name: secure-runtime

Handler: runsc
```yaml
   apiVersion: node.k8s.io/v1
   handler: runsc
   kind: RuntimeClass
   metadata:
     name: secure-runtime
```
-A pod definition file is provided at /root/simple-webapp-1.yaml. Update this file with the runtime class that we just created in the previous step.
runtimeClassName: secure-runtime
```yaml
  apiVersion: v1
kind: Pod
metadata:
    name: simple-webapp-1
    labels:
        name: simple-webapp
spec:
   runtimeClassName: secure-runtime
   containers:
     - name: simple-webapp
       image: kodekloud/webapp-delayed-start
       ports:
        - containerPort: 8080
```
## Implementing Resource Quotas in Kubernetes

-Define and Apply a Resource Quota for Team A
There is a new team in the organization team-a which requires a resource quota to limit the resource usage within their namespace.

This will help to ensure that the team does not consume more resources than allocated, and prevent resource contention with other teams.

Create a resource quota file for team-a with the following resource limits:

Name: team-a-resource-quota
Maximum of 5 pods
CPU requests: 0.5
Memory requests: 500Mi
CPU limits: 1
Memory limits: 1Gi

```yaml
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: team-a-resource-quota
  namespace: team-a
spec:
  hard:
    pods: 5
    requests.cpu: "0.5"
    requests.memory: "500Mi"
    limits.cpu: "1"
    limits.memory: "1Gi"
```
- Deploy a pod in the team-a namespace.
Use the following pod configuration as a starting point:

apiVersion: v1
kind: Pod
metadata:
  name: app-pod
  namespace: team-a
spec:
  containers:
  - name: app-container
    image: nginx
    ports:
    - containerPort: 80

Its expected that the pod will be subject to the resource limits defined in the resource quota for team-a.

Assign following resource requests and limits to the pod:

CPU requests: 0.1
Memory requests: 10Mi
CPU limits: 0.2
Memory limits: 50Mi

```yaml
---
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
  namespace: team-a
spec:
  containers:
  - name: app-container
    image: nginx
    ports:
    - containerPort: 80
    resources:
      requests:
        memory: "10Mi"
        cpu: "0.1"
      limits:
        memory: "50Mi"
        cpu: "0.2"
```

- Monitor Resource Usage in Team A
How to verify quota usage for the team-a namespace for the resource quota team-a-resource-quota?
```bash
kubectl describe quota team-a-resource-quota -n team-a
```
- What is the main purpose of a Resource Quota in Kubernetes?
  to restrict the amout of resources in a namespace can be consumed

## Securing Network Traffic with Network Policies

- Which OSI layer does Kubernetes Network Policies not operate on?
   Data link Layer
- Your task is to create and label three namespaces: namespace-web, namespace-worker, and namespace-ui. Please ensure to label them as follows:

namespace=namespace-web
namespace=namespace-worker
namespace=namespace-ui
Subsequently, deploy the following pods:

An Nginx web server pod named nginx-pod in namespace-web with the image nginx.
A busybox pod named busybox-pod in namespace-worker with the image busybox, using the command sleep 7600.
A pod named ui-pod in namespace-ui using the image traefik/whoami.
Make sure to follow the specified structure for namespaces and pods.

```bash
k create ns namespace-worker
k label namespaces namespace-wórker namespace=namespace-worker --overwrite=true
k run nginx-pod --image=nginx -n namespace-web
k run ui-pod -n namespace-ui --image=traefik/whoami
k run busybox-pod --image=busybox -n namespace-worker --command sleep 7600
k apply -f busybox-pod.yml 
```
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: busybox-pod
  name: busybox-pod
  namespace: namespace-worker
spec:
  containers:
  - image: busybox
    name: busybox-pod
    command: ["sleep"]
    args: ["7600"]
    resources: {}
  dnsPolicy: ClusterFirst
  restartPolicy: Always
status: {}
```

- Test the connectivity between the busybox-pod in namespace-worker and the nginx-pod in namespace-web before applying any Network Policies.

Get the Cluster IP of the nginx-pod in namespace-web.
Exec into busybox-pod in namespace-worker and use wget to test connectivity to the Nginx pod.
Exec into busybox-pod in namespace-worker and use wget to test connectivity to the Traefik-Whoami pod.

```bash
# Get the Cluster IP of `nginx-pod`
NGINX_IP=$(kubectl get pod nginx-pod -n namespace-web -o jsonpath='{.status.podIP}')

# Test Connectivity from `busybox-pod`
kubectl exec -it busybox-pod -n namespace-worker -- wget -qO- http://$NGINX_IP

UI_IP=$(kubectl get pod ui-pod -n namespace-ui -o jsonpath='{.status.podIP}')
# Test Connectivity from `busybox-pod`
kubectl exec -it busybox-pod -n namespace-worker -- wget -qO- http://$UI_IP
```

- Create a Network Policy named allow-specific-ingress in the namespace-ui namespace.

This policy should:

Allow ingress traffic only from pods in the namespace-web namespace
Deny traffic from all other namespaces (implicit deny via network policy behavior)
Apply only to pods inside the namespace-ui namespace
You must create the manifest file named np2.yaml yourself and use it to apply the policy.

Requirements
Network Policy Name: allow-specific-ingress
Namespace: namespace-ui
Policy Type: Ingress
Ingress Rules: Allow traffic only from namespace-web namespace
After creating the manifest, apply it to the cluster.
```yaml
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-specific-ingress
  namespace: namespace-ui
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              namespace: namespace-web
```
- Deny egress traffic from namespace-worker to external sites (internet) using a Network Policy.
Allow egress traffic from namespace-worker only to internal services in the cluster.
Create a Network Policy named deny-external-egress in namespace-worker.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-external-egress
  namespace: namespace-worker
spec:
  podSelector: {}  # Selects all pods in namespace-worker 
  policyTypes:
  - Egress
  egress:
  # Allow egress to all pods in all namespaces
  - to:
    - namespaceSelector: {}  # All namespaces
      podSelector: {}        # All pods
```
```bash
kubectl apply -f deny-external-egress.yaml
# This should fail due to the Network Policy blocking the connection.
kubectl exec -it test-pod -n namespace-worker -- 'wget -qO- http://google.com || echo "Failed"'
```
## Implement Tenant Isolation in a Kubernetes Cluster

- Taint Nodes for Tenant Isolation
Apply taints to all the worker nodes in your Kubernetes cluster to enforce tenant isolation.

Taint labels:
team=team-a on node01
team=team-b on node02
team=team-c on node03
This will ensure that only pods with the appropriate tolerations can be scheduled on specific nodes.

```
  kubectl taint nodes node01 team=team-a:NoSchedule
  kubectl taint nodes node02 team=team-b:NoSchedule
  kubectl taint nodes node03 team=team-c:NoSchedule
  
```
- Create the following namespaces to organize resources and enforce boundaries:

team-a
team-b
team-c
```
  k create ns team-a
  k create ns team-b
  k create ns team-c
```
- Deploy Pods with Tolerations

For each team namespace, deploy a pod with the appropriate tolerations so that it can be scheduled on its designated node.

team-a
Name: team-a-pod
Namespace: team-a
Tolerations: team=team-a:NoSchedule
Image: nginx
team-b
Name: team-b-pod
Namespace: team-b
Tolerations: team=team-b:NoSchedule
Image: nginx
team-c
Name: team-c-pod
Namespace: team-c
Tolerations: team=team-c:NoSchedule
Image: nginx
```yaml
   apiVersion: v1
kind: Pod
metadata:
  labels:
    run: team-a-pod
  name: team-a-pod
  namespace: team-a
spec:
  containers:
  - image: nginx
    name: team-a-pod
    resources: {}
  dnsPolicy: ClusterFirst
  restartPolicy: Always
  tolerations:
    - key: team
      operator: Equal
      value: team-a
      effect: NoSchedule
status: {}
```
- Verify that each team's pod is scheduled on the correct node.

Run the following commands to check the node assignments:

kubectl get pods -n team-a -o wide
kubectl get pods -n team-b -o wide
kubectl get pods -n team-c -o wide

Ensure that:

team-a-pod is running on node01
team-b-pod is running on node02
team-c-pod is running on node03

 Attempt to deploy a pod without the appropriate tolerations in the team-a namespace and observe the scheduling behavior.

Determine if the pod is scheduled or remains in the Pending state.
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: team-a
spec:
  containers:
  - image: nginx
    name: team-a-pod
    resources: {}
  dnsPolicy: ClusterFirst
  restartPolicy: Always
```
- In which scenario would using node taints and tolerations not be appropriate from the options listed below?
  to allow unrestricted scheduling pods on any node
- How can node taints and tolerations help during cluster maintenance activities?
  By preventing new pods from being scheduled on the node while allowing existing pods to continue running.
- Remove the taints from the nodes:

node01
node02
node03
```
  kubectl taint nodes node01 team=team-a:NoSchedule-
  kubectl taint nodes node02 team=team-b:NoSchedule-
  kubectl taint nodes node03 team=team-c:NoSchedule-
```
