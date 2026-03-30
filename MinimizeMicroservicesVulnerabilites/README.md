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
