# cks-prep

## CIS benchmark:
CIS: Center of Internet Security
command to run assessment report for cis benchmark
```
sh /root/Assessor/Assessor-CLI.sh -i  -nts -rd /var/www/html/ -rp index
```
## kube-bench:
Its a product of aqua security.kube-bench is a tool that checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes Benchmark.
- install kube bench
  ```
  KUBE_BENCH_VERSION=0.10.1
  curl -L https://github.com/aquasecurity/kube-bench/releases/download/v${KUBE_BENCH_VERSION}/kube-bench_${KUBE_BENCH_VERSION}_linux_amd64.deb -o kube-    bench_${KUBE_BENCH_VERSION}_linux_amd64.deb
  sudo apt install ./kube-bench_${KUBE_BENCH_VERSION}_linux_amd64.deb -f
  ```
- run kube-bench against all targets
  ```
  kube-bench
  ```
- to check specific test on kube-bench
  ```
  kube-bench --check="1.3.1"
  ```
- run kube-bench for only for target group
  ```
  kube-bench run --targets="master"
  kube-bench run --targets="master,etcd"
  ```
## Service Account
  - create service account with
    ```
    k create sa
    ```
  - Command to generate the token for dashboard sa(serrvice account)
    ```
    kubectl create token dashboard-sa
  ```
  - edit deploymen with new sa
  ```
  k edit deploymend web-dashboard
  ```
  add service account name under template spec of deployment spec section
  ```yaml
  serviceAccountName: dashboard-sa
  ```
## View Certificates

- Common Name (CN) configured on the Kube API Server Certificate?
```
OpenSSL Syntax: openssl x509 -in file-path.crt -text -noout
```
to get the CA name see the issuer of the certificate

## Certificate API
- convert csr into base64 format withour widespace
    ```
   cat akshay.csr | base64 -w 0
   ```
- sample csr
```yaml
---
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: akshay
spec:
  groups:
  - system:authenticated
  request: <Paste the base64 encoded value of the CSR file>
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
```
```bash
kubectl explain certificatesigningrequest.spec.usages
k certificate approve akshay
k certificate deny agent-smith
k delete csr agent-smith
```
## Kube-config

- default kube config location
/root/.kube/config

- command to view kube config
```
k config view
```
- command to view custom kube config
```
 kubectl config view --kubeconfig my-kube-config
```
- command to set another context in kuberntes
```
kubectl config use-context
```
To use that context, run the command:
```
kubectl config --kubeconfig=/root/my-kube-config use-context research
```

To know the current context, run the command:

```
kubectl config --kubeconfig=/root/my-kube-config current-context
```
export KUBECONFIG=/root/my-kube-config

## Access kube-api server

start kube-proxy
kubectl proxy --port 8090 &

to kill the kubectl proxy process
```
pkill -f "kubectl proxy"
ps aux | grep 'kubectl proxy' | grep "8090"
kill <process_id>

```

## Bootstrap token for authentication:
Sample yaml
```yaml
apiVersion: v1
data:  auth-extra-groups: c3lzdGVtOmJvb3RzdHJhcHBlcnM6a3ViZWFkbTpkZWZhdWx0LW5vZGUt
dG9rZW4K
  token-id: MDc0MDFiCg==
  token-secret: ZjM5NWFjY2QyNDZhZTUyZAo=
  usage-bootstrap-authentication: dHJ1ZQ==
  usage-bootstrap-signing: dHJ1ZQ==
kind: Secret
metadata:
  name: bootstrap-token-07401b
  namespace: kube-system
type: bootstrap.kubernetes.io/token
```
On the control plane node, use kubeadm to generate the join command that includes a random bootstrap token:

```
kubeadm token create [random-token-id].[random-secret] --dry-run --print-join-command --ttl 2h
```

## Retrieve Service Account token and use it to access API server
service account token secret yaml. Annotation here in yaml associate this secret with specific service account in annotation.
create service account and automount service account with associated secret with secrets field as shown here.
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
  namespace: default
secrets:
  - name: my-service-account-token
---
apiVersion: v1
kind: Secret
metadata:
  name: my-service-account-token
  namespace: default
  annotations:
    kubernetes.io/service-account.name: "my-service-account"
type: kubernetes.io/service-account-token
```
create role and rolebinidng via command line
```
kubectl create role pod-reader --verb=get --verb=list --verb=watch --resource=pods
kubectl create rolebinding read-pods --role=pod-reader --serviceaccount=default:my-service-account
```
verify if the service account have enough rights to read the pods
```
kubectl auth can-i list pods --as=system:serviceaccount:default:my-service-account
```
to access kube-api server via token and cacertificate
Get the API Server Endpoint:
```
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
```
Get the CA Certificate:
```
CACERT=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.certificate-authority}')
```
If the CA certificate is embedded in your kubeconfig, extract it:
```
kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 --decode > ca.crt
```
Retrieve the Token:
```
SECRET_NAME=$(kubectl get serviceaccount my-service-account -o jsonpath='{.secrets[0].name}')
TOKEN=$(kubectl get secret $SECRET_NAME -o jsonpath='{.data.token}' | base64 --decode)
```
Use curl to Access the API Server:
```
curl --cacert ca.crt -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/default/pods"

```
## RBAC
- to get authorization mode to kube-apiserver check kube-apiserver.yaml manisfest file
- to get no of roles in all namespaces
  ```bash
  k get roles -A --no-headers| wc -l
  ```
## Clusterrole and Clusterrolebinding

```yaml
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: node-admin
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "watch", "list", "create", "delete"]

---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: michelle-binding
subjects:
- kind: User
  name: michelle
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: node-admin
  apiGroup: rbac.authorization.k8s.io
```
to test if michelle has enough permissions:
```
kubectl auth can-i list storageclasses --as michelle
```
## ABAC
- to get apiVersion of any kubernetes object just run this command
 ```
  kubectl api-versions
  ```
- ABAC file format is one JSON object per line
- example
  ```jsonl
  {"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{"user":"system:serviceaccount:default:john","namespace":"default","resource":"pods","apiGroup":"*","readonly": true }}
  ```
  - enable ABAC
    ```
  --authorization-policy-file=/path/to/abac-policy.jsonl
  --authorization-mode=Node,RBAC,ABAC
  ```
```bash
# Get the secret name
kubectl get serviceaccount john -o jsonpath='{.secrets[0].name}'

# Retrieve the token
kubectl get secret john-secret -o jsonpath='{.data.token}' | base64 --decode

# Save the token to a file
kubectl get secret john-secret -o jsonpath='{.data.token}' | base64 --decode > john-secret.txt
```
## Kubelet-Security:
- To get the kubelet configuration file
  ```
  ps -aux|grep kubelet
  ```
- to get particular value in kubelet configuration file
  ```
  cat /var/lib/kubelet/config.yaml|grep rotateCertificates
  ```
- kubelet full access at 10250 port and read only access at 10255

- to check kubelet allow requests for anonymous users?check kubelet config file and see if anonmymous is enabled or not
  ```
  authentication:
  anonymous:
    enabled: true
  ```
- to check kind of authorization enabled at kubelet, check kubelet config file again
- call the pod apis using curl -sk https://localhost:10250/pods
- restart kubelet after any change in kubelet config file using systemctl restart kubelet
- to check metrics on readOnlyPort with curl -sk http://localhost:10255/metrics
- to disable the metrics on readonlyport set property readOnlyPort to 0 in kubelet config file and restart kubelet

## Kubectl proxy and forward
- to start kubectl proxy on default port
  ```
  kubectl proxy &
  ```
- Call the API endpoint /version of kubectl proxy using curl and redirect the output to the file: /root/kube-proxy-version.json
  ```
  curl 127.0.0.1:8001/version > /root/kube-proxy-version.json
  ```
- to kill running kubectl proxy process
  ```
  ps -aux|grep proxy
  kill -1 13421
  ```
- command can forward a local port to a port on the Pod ?
  ```
  kubectl port-forward
  ```
- command to forward port 8000 on the host to port 5000 on the pod app?

```
 # Listen on port 8888 on all addresses, forwarding to 5000 in the pod
  kubectl port-forward  pod/mypod 8888:5000
```

- We deployed nginx app in default namespace. Wait few seconds for pod to spinup.Forward port 8005 of localhost to port 80 of nginx pods. Run port-forward process in background.Try accessing port 8005 after port forwarding.

```
   k port-forward deployments/nginx 8005:80 &
   curl localhost:5000
```

First get all resource names for nginx using the command:
```
 kubectl get all
```
Run any of below commands with valid names
```
kubectl port-forward pods/{POD_NAME} 8005:80 &
```
OR
```
kubectl port-forward deployment/{DEPLOYMENT_NAME} 8005:80 &
```
OR
```
kubectl port-forward service/{SERVICE_NAME} 8005:80 &
```
OR
```
   kubectl port-forward replicaset/{REPLICASET_NAME} 8005:80 &
```

- then try curl localhost:8005 to check nginx response
-  kubectl proxy - Opens proxy port to API server

- kubectl port-forward - Opens port to target deployment pods

## Verify Platform Binaries

- to download kubernetes binaries to specific folder
  ```
  wget -O /opt/kubernetes.tar.gz https://dl.k8s.io/v1.34.1/kubernetes.tar.gz
  ```
- to get shassum512 of the binary file
  ```
  sha512sum kubernetes.tar.gz
  ```
get valid spec fields kubernetes via command line for add sys_time capability

## Kubeadm Cluster Upgrade
- to make the node unschedulable(scheduling disabled)
  ```
  kubectl cordon controlplane
  ```
- to check the latest available version for upgrade
  ```
  kubeadm upgrade plan
  ```
- Step 1: Update the repository with new version:
  ```
  pager /etc/apt/sources.list.d/kubernetes.list
  deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.33/deb/ /
  ```
  
- Step:2 to determine the latest patch release for Kubernetes 1.34 using the OS package manager:
  ````
  sudo apt-update
  sudo apt-cache madison kubeadm
  ```
- Step 3: Upgrade controlplane node
  ```
    sudo apt-mark unhold kubeadm && \
    sudo apt-get update && sudo apt-get install -y kubeadm='1.34.0-1.1' && \
    sudo apt-mark hold kubeadm
  ```
- Step 4: Check the Kubeadm version
  ```
  kubeadm version
  ```
- Step 5: Verify the upgrade plan
  ```
  sudo kubeadm upgrade plan
  ```
- Step 6: run the upgrade
  ```
    sudo kubeadm upgrade apply v1.34.0
  ```
- Step 7: Upgrade the kubelet and kubectl
  ```
  sudo apt-mark unhold kubelet kubectl && \
  sudo apt-get update && sudo apt-get install -y kubelet='1.34.0-1.1' kubectl='1.34.0-1.1' && \
  sudo apt-mark hold kubelet kubectl
  ```
- Step 8: retart the kubelet
  ```
    sudo systemctl daemon-reload
    sudo systemctl restart kubelet
  ```
- Step 9: UnCordon the node
  ```
    kubectl uncordon controlplane
  ```
- Step 10: Upgrade worker nodes
  same as controlplane

## NetworkPolicies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: internal-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      name: internal
  policyTypes:
  - Egress
  - Ingress
  ingress:
    - {}
  egress:
  - to:
    - podSelector:
        matchLabels:
          name: mysql
    ports:
    - protocol: TCP
      port: 3306

  - to:
    - podSelector:
        matchLabels:
          name: payroll
    ports:
    - protocol: TCP
      port: 8080

  - ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
```
## Ingress
- to get the ingress resources in all namespaces
  ```
  kubectl get ingress --all-namespaces
  ```

- command to create ingress resource via command line
  ```
  kubectl create ingress app-ingress -n app-space --rule="/wear=wear-service:8080" --rule="/watch=video-service:8080" --annotation nginx.ingress.kubernetes.io/rewrite-target=/ --dry-run=client -o yaml > ingress-resource.yaml
  ```
- to annotate existing ingress
  ```
  kubectl annotate ingress web-app-ingress -n webapp nginx.ingress.kubernetes.io/ssl-redirect="true"
  ```
- Verify the complete Ingress configuration. The Ingress should route traffic for app.kodekloud.local to the web-app Service, with TLS termination using app-tls and HTTP to HTTPS redirect enabled.

Check the Ingress details:
```
kubectl -n webapp get ingress
kubectl -n webapp describe ingress web-app-ingress
```

You can test the Ingress configuration with:
```
curl -Lk https://app.kodekloud.local
```

## Implementing node metadata protection:
- Create a NetworkPolicy named deny-metadata in the default namespace that denies egress traffic from the app pod to the AWS Metadata Service running at <controlplane-ip>:9999.

The NetworkPolicy should:

Select the app pod (using appropriate labels).
Deny egress traffic to controlplane IP.
Allow all other egress traffic.
Use a YAML manifest to create the NetworkPolicy.


Note:
To get the IP of controlplane, run the following command:
Get the IP address of the controlplane node:
```
CONTROLPLANE_IP=$(kubectl get node controlplane -o jsonpath="{.status.addresses[0].address}")
echo $CONTROLPLANE_IP
```
Create a YAML file named deny-metadata.yaml with the following content:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: app
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - <controlplane-ip>/32 # Replace with the actual IP address of the controlplane node
```

Apply the manifest:
```bash
kubectl apply -f deny-metadata.yaml
```
This NetworkPolicy allows egress traffic to all destinations except for the controlplane IP address where the AWS Metadata Service is running.

## Setting Access Controls for Node Metadata via RBAC
- command to create cluster roles
  ```
  kubectl create clusterrole node-viewer --verb=get,list,watch --resource=nodes
  ```
- access curl inside the pod using:
  ```
  kubectl exec -it api-test-pod -n default -- /bin/bash -c 'curl -k https://kubernetes.default.svc/api/v1/nodes -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"'
  ```
# System Hardening

## Limit Node Access
- command to list id of user
  ```
  id
  ```
- command to list information of existing user
  ```
  cat /etc/passwd | grep mail
  ```
- command to change password of user
  ```
  passwd david
  ```
- command to delete user name ray
  ```
  deluser ray
  ```
- command to delete group
  ```
  delgroup devs
  ```
- command to modify shell for user
  ```
  usermod himanshi -s /usr/sbin/nologin
  ```
- Create a user named sam on the controlplane host. The user's home directory must be /opt/sam. Login shell must be /bin/bash and uid must be 2328. Make sam a member of the admin group.
  ```
  useradd sam -d /opt/sam -s /bin/bash -u 2328 -G admin
  ```

  ## SSH hardening with sudo
  - default scp port 22
  - to provide private key while ssh login we can use ssh -i command to pass private key
  - different authentication method is available to login to ssh  such as via public key authentication, password based authentication and None
  - to enable passwordless authentication to node01(Create a user named jim on node01 host and configure password-less ssh access from controlplane host (from user root) to node01 host (to user jim).)
    ```
    ssh into node01 host from controlplane host
    ssh node01

    Create user jim on node01 host
    adduser jim (set any password you like)

    Return back to controlplane host and copy ssh public key
    ssh-copy-id -i ~/.ssh/id_rsa.pub jim@node01

    Test ssh access from controlplane host
    ssh jim@node01
    ```
- to make jim a sudo user
    On node01 host, open /etc/sudoers file using any editor like vi and add an entry for user jim and forcefully save the file.
    ```
     jim    ALL=(ALL:ALL) ALL
   ```
- to make jim to run sudo without entering password
  ```
  jim  ALL=(ALL) NOPASSWD:ALL
  ```
- to make user a member of admin group without changing sudoers file
  ```
  usermod rob -G admin
  ```
- There is some issue with sudo on node01 host, as user rob is not able to run sudo commands, investigate and fix this issue.
  Password for user rob that we set in the previous question: jid345kjf

  ```
  node01 ~ ➜  sudo su -
  node01 ~ ➜  su rob
  \[\]node01\[\] \[\]~\[\] \[\]➜\[\]  sudo apt-get update
   [sudo] password for rob: 
   rob is not in the sudoers file.  This incident will be reported.
   sudo visudo
   %admin ALL=(ALL) ALL

```
- to disable ssh root login and disable password authentication for ssh on node01 host,default location of sshd config /etc/ssh/sshd_config
```
PermitRootLogin No
PasswordAuthentication No
```

- restart sshd service
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
## kubelinter
KubeLinter analyzes Kubernetes YAML files and Helm charts and checks them against various best practices, with a focus on production readiness and security.

to install kubelinter
```bash
curl -LO https://github.com/stackrox/kube-linter/releases/download/v0.8.1/kube-linter-linux.tar.gz
tar -xvf kube-linter-linux.tar.gz
mv kube-linter /usr/local/bin/
```
to use kube-linter
```bash
kube-linter lint /root/nginx.yaml > /root/analyze
```
apply security context, resource quota for pods:
```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      affinity:                                               #added
        podAntiAffinity:                                      #added
          requiredDuringSchedulingIgnoredDuringExecution:     #added
          - labelSelector:                                    #added
              matchExpressions:                               #added
              - key: app                                      #added
                operator: In                                  #added
                values:                                       #added
                - nginx                                       #added
            topologyKey: "kubernetes.io/hostname"             #added
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
        securityContext:
          readOnlyRootFilesystem: true
          runAsUser: 1000
          runAsNonRoot: true
```
## enable ImagePolicyWebhook

- Add this to kube api server manifest file
```
 - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
 - --admission-control-config-file=/etc/kubernetes/pki/admission_configuration.yaml
```
## kubesec
kubesec is used to scannung kubernetes objects such as damenonsets, deployments,replicasets.
Steps to install kubesec on linux machine:
```bash
wget https://github.com/controlplaneio/kubesec/releases/download/v2.13.0/kubesec_linux_amd64.tar.gz

tar -xvf  kubesec_linux_amd64.tar.gz

mv kubesec /usr/bin/
```
> Note: Kubesec dont support bash

kubesec command to scan the yaml:
```bash
kubesec scan node.yaml > /root/kubesec_report.json
```

## Trivy
Trivy is a comprehensive and versatile security scanner. Trivy has scanners that look for security issues, and targets where it can find those issues.
Installation
```bash
sudo apt-get install wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```
> Reference: https://github.com/aquasecurity/trivy

command to get trivy version:

```bash
trivy version
```
command to scan image via trivy and store it in output file:
```
# Scan the vulnerability
trivy image --output /root/python_12.txt public.ecr.aws/docker/library/python:3.12.4
```

Scan the image and filter only hight severity issue using:
```
trivy image --severity HIGH --output /root/python.txt public.ecr.aws/docker/library/python:3.9-bullseye
```
command to scan tar file
```
trivy image --input alpine.tar --output /root/alpine.json
```
command to get output in json format

```
trivy image --input alpine.tar --format json --output /root/alpine.json
```
## immutability of containers at the runtime

- Check if the pods are running with read-only root and do not use elevated privileges.
- To confirm from the YAML, look for volume mounts and securityContext settings:

If there's a hostPath or emptyDir mounted at / (which is rare and risky), it could allow writing.
Check if securityContext has 

privileged: true or 
allowPrivilegeEscalation: true 

which can give the container elevated permissions, potentially enabling root write access.

> notes: default, containers can write to the filesystem unless explicitly restricted, especially if they run as root.
         So, unless securityContext restricts this, the container might still have root privileges and can write to /.

to insopect a pod and its reasons of failure:
```bash
k logs triton -n alpha
```
pod to set emptyDir volume for pod
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    name: triton
  name: triton
  namespace: alpha
spec:
  containers:
  - image: httpd
    name: triton
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - mountPath: /usr/local/apache2/logs
      name: log-volume
  volumes:
  - name: log-volume
    emptyDir: {}
```
## audit log monitor access
- highest events logged by requestresponse level
- audit is managed by kube-apiserver via --audit-policy-file and -audit-max-age in kube-apiserver.yaml file
- sample audit file
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
```
to get schema of policy:
```bash
kubectl explain policy --api-version=audit.k8s.io/v1
```
to discover flags in kubernetes
```
kube-apiserver --help | grep audit
kubectl -n kube-system exec -it kube-apiserver-<node-name> -- kube-apiserver --help | grep audit
```

Now enable auditing in this Kubernetes cluster. Create a new policy file and set it to Metadata level and it will only log events based on the below specifications:


Namespace: prod

Operations: delete

Resources: secrets

Log Path: /var/log/prod-secrets.log

Audit file location: /etc/kubernetes/prod-audit.yaml

Maximum days to keep the logs: 30

```
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  namespaces: ["prod"]
  verbs: ["delete"]
  resources:
  - group: ""
    resources: ["secrets"]
```
Next, make sure to enable logging in api-server:
```
 - --audit-policy-file=/etc/kubernetes/prod-audit.yaml
 - --audit-log-path=/var/log/prod-secrets.log
 - --audit-log-maxage=30
```
Then, add volumes and volume mounts as shown in the below snippets.

volumes:
```
  - name: audit
    hostPath:
      path: /etc/kubernetes/prod-audit.yaml
      type: File

  - name: audit-log
    hostPath:
      path: /var/log/prod-secrets.log
      type: FileOrCreate
```
volumeMounts:
```
  - mountPath: /etc/kubernetes/prod-audit.yaml
    name: audit
    readOnly: true
  - mountPath: /var/log/prod-secrets.log
    name: audit-log
    readOnly: false
```
## falco
Falco is a cloud native security tool that provides runtime security across hosts, containers, Kubernetes, and cloud environments. It is designed to detect and alert on abnormal behavior and potential security threats in real-time.

To determine if Falco is installed as a daemonset or a package, you can:

Check for a DaemonSet in the kube-system namespace:
```
  kubectl get daemonset -n kube-system | grep falco
```

Or verify if it's installed as a package on the node:
```
  systemctl status falco
```

Since the hint suggests running systemctl status falco, it's likely installed as a package on the control plane node.
- to check if falco is installed
  ```
  systemctl status falco
  ```
- default falco config file
  /etc/falco/falco.yaml
- to check out format check variable json_output in falco.yaml. if it is set to false , means output format is text.

- if same rules is defined in multiple files then the rules that comes last is valid
- kubectl get pods -A -o json | jq -r '.items[] | "\(.metadata.namespace),\(.metadata.name)"'
- kubectl get pods -A -o json | jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name, status: .status.phase}'
- to reload falco
```
 kill -1 $(cat /var/run/falco.pid)
```
Other important commands
```
 falco -L
 falco --list
 falco --list-events
```

  
