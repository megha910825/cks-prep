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

