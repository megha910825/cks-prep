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

  
