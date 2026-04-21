# Supply Chain Security

## Creating and Analyzing SBOMS

- supply chain security by providing transparency and allowing organizations to identify and address vulnerabilities efficiently.

SBOMs enable:

Better management of software dependencies,
Improved compliance with licensing requirements,
Quick responses to security threats.
By adopting SBOMs, organizations can enhance their security posture and reduce risks associated with third-party software components.

- Download the Syft tool and move the binary to /usr/local/bin.
```
  curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
```

- Generate an SBOM for the docker.io/kodekloud/webapp-color:latest image in SPDX format using Syft and store it in /root/webapp-spdx.sbom.
```
  syft docker.io/kodekloud/webapp-color:latest -o spdx=/root/webapp-spdx.sbom  
```
- Generate an SBOM for the docker.io/kodekloud/webapp-color:latest image in CycloneDX JSON format using Syft and store it in /root/webapp-sbom.json.

```
  syft docker.io/kodekloud/webapp-color:latest -o cyclonedx-json=/root/webapp-sbom.json
```

- Download the Grype tool and move the binary to /usr/local/bin.
```
  curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
```

- Analyze the /root/webapp-sbom.json SBOM using Grype to generate a vulnerability report and store it in /root/grype-report.json.
```
grype sbom:/root/webapp-sbom.json --output json | jq . > /root/grype-report.json
```
- Examine the /root/grype-report.json report and find the total number of Critical vulnerabilities that exist.
```
   cat /root/grype-report.json | jq '[.matches[]|select(.vulnerability.severity=="Critical")]|length'
```

- Examine the /root/grype-report.json report and find the severity level assigned to the vulnerability CVE-2022-48174.
```
  cat grype-report.json | jq -e '.matches[] | select(.vulnerability.id == "CVE-2022-48174")'
```
- The vulnerability CVE-2018-1000517 in BusyBox wget may lead to which type of security issue?
Heap Buffer overflow(see the vulnerability in json file)

## Automating SBOM Generation in CI/CD
- Follow the instructions below to configure your GitHub credential before going to the next questions.
  Open the lab console and configure following environment variables with your own GitHub account information:

vi /root/github_repo_info.json
{
    "REPO_OWNER": "your_username_here",
    "ACCESS_TOKEN": "your_access_token_here"
}

The provided information will solely be utilized for validating your response in the next question. Please note, we do not retain this information for any other purposes.
Refer to this document if you're not sure how to get your own access token: Managing your personal access tokens.

- Fork the Repository - https://github.com/iampsrv/supply_chain_security to use as a starting point.

Note that the Repository name is supply_chain_security (do not change it).
Go through the repository. It contains nginx-sbom.json, nginx-spdx.sbom and a .github/workflows directory.
Explore the main.yml file.
Enable GitHub Actions

- Modify the workflow in main.yml to generate an SBOM report for the docker.io/kodekloud/webapp-color:latest image in SPDX-JSON format and store it in spdx.json.

Also, change actions/upload-artifact@v3 to actions/upload-artifact@v4.

```yaml
  name: Generate SBOM Report with Syft

on:
  push:
    branches:
      - master
  pull_request:
    branches:
      - master

jobs:
  generate-sbom:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout Repository
      uses: actions/checkout@v3

    - name: Install Syft
      run: |
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

    - name: Generate SBOM                      #Modified
      run: |
        syft docker.io/kodekloud/webapp-color:latest -o spdx-json > spdx.json  

    - name: Upload SBOM Artifact
      uses: actions/upload-artifact@v4
      with:
        name: sbom-report
        path: sbom.xml
```
- Modify the workflow in main.yml to upload the artifact spdx.json in the Upload SBOM Artifact step and configure the workflow to trigger manually.


NOTE: After committing the changes, monitor the workflow to observe the process.
Note: It may take some time for the artifact to be ready. Validation attempts will fail until the artifact becomes available.

```yaml
  name: Generate SBOM Report with Syft

on:
  workflow_dispatch:     #added fir manuall trigger
  push:
    branches:
      - master
  pull_request:
    branches:
      - master

jobs:
  generate-sbom:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout Repository
      uses: actions/checkout@v3

    - name: Install Syft
      run: |
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

    - name: Generate SBOM
      run: |
        syft docker.io/kodekloud/webapp-color:latest -o spdx-json > spdx.json

    - name: Upload SBOM Artifact
      uses: actions/upload-artifact@v4
      with:
        name: spdx-report
        path: spdx.json       #modified
```
## Performing Static Analysis with KubeLinter

- Download the latest release of KubeLinter for Linux and move the binary to the /usr/local/bin/ path.
```
 # Download the latest version of KubeLinter for Linux using the command below:
curl -LO https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux.tar.gz
# Extract the binary from the tar file:
tar -xvf kube-linter-linux.tar.gz
# Move the binary to the /usr/local/bin/ path:
mv kube-linter /usr/local/bin/
```
- Analyze a Kubernetes Manifest stored in /root/nginx.yml and store the result in /root/analyze
  ```
  kube-linter lint /root/nginx.yml>/root/analyze
  ```
- If memory limits are not set for the nginx container, what could be the potential consequence?
  the container will have unlimited access to node memory, risking node instability if it consumes too much.

- What is the likely impact of not setting CPU requests for the nginx container?
  the container may compete for cpu with other containers, leading to unstable performance

- 7 / 17
Based on the results from KubeLinter, let's implement the best practices in the /root/nginx.yml file.

Set resource requests:

cpu: 250m
memory: 64Mi
Set resource limits:

cpu: 500m
memory: 128Mi

```yaml
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
```
- What is the risk if the nginx container does not have a read-only root filesystem?
  Without a read-only root filesystem, the container's root filesystem is writable, which increases security risks. An attacker or process could modify files in the root filesystem, leading to potential vulnerabilities. Setting the root filesystem to read-only prevents these unauthorized modifications.

- What could happen if the nginx container is not set to run as a non-root user?
  the container possesses elevated priviledges , which may highten its vulnerability of attacks.
  
- Based on the results from KubeLinter, let's implement the best practices in the /root/nginx.yml file.
  Enable a read-only root filesystem.
  Configure to run as a non-root user.
  ```yaml
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
        securityContext:               #added
          readOnlyRootFilesystem: true #added
          runAsUser: 1000              #added
          runAsNonRoot: true           #added
  ```
- What will happen if inter-pod anti-affinity is not specified in the nginx deployment configuration?
the pod might scheduled all on the same node, risking all replicas failing, if that node fails.
- 12 / 17
Based on the results from KubeLinter, let's implement the best practices in the /root/nginx.yml file.

In the /root/nginx.yml file, implement anti-affinity in your pod specification to ensure that the orchestrator schedules replicas on different nodes.
Use the app: nginx label.
Set the topologyKey to kubernetes.io/hostname
```yaml
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
- After implementing all the best security practices, analyze the /root/nginx.yml file again.
How many recommendations are suggested?
- Review the Dockerfile at /cks/docker/Dockerfile. What is the prominent security issue with the USER instruction in this file?
The Dockerfile contains USER root, which means the container process runs as the root user. This is a significant security risk because if an attacker gains access to the container, they will have full root privileges, which could allow them to escape the container or compromise the host system. The best practice is to run containers as a non-root user.

- Next

15 / 17
Analyze and edit the Dockerfile at /cks/docker/Dockerfile.

Fix the one instruction that has a prominent security / best-practice issue.

Do not add or remove any instructions.
Only modify the existing instruction.
If you need to a use non-root user , use user www-data
The security issue is the USER root instruction. The container should not run as root.
Answer:
Edit the Dockerfile and change:

USER root
to a non-root user, for example:

USER www-data
This ensures the container runs as a non-privileged user instead of root.

- Review the deployment manifest at /cks/docker/deployment.yaml. What is the prominent security issue with the securityContext in this file?
  allowPriviledgeEscalation is true

- Analyze and edit the deployment manifest at /cks/docker/deployment.yaml.

Fix the one field that has a prominent security / best-practice issue.

Do not add or remove any configuration settings.
Only modify the existing field.

Answer: The security issue is allowPrivilegeEscalation: true. This allows container processes to gain additional privileges.

Edit the deployment manifest and change:

allowPrivilegeEscalation: true
to:

allowPrivilegeEscalation: false
This prevents any process inside the container from gaining more privileges than its parent, which is a critical security hardening measure.

## Image Security

- What secret type must we choose for docker registry?
  docker-registry
- We have an application running on our cluster. Let us explore it first. What image is the application using?
  ```
  k get deploment web -o yaml
  ```
- We decided to use a modified version of the application from an internal private registry. Update the image of the deployment to use a new image from myprivateregistry.com:5000
The registry is located at myprivateregistry.com:5000. Don't worry about the credentials for now. We will configure them in the upcoming steps.

```bash
  k set image deployments/web nginx=myprivateregistry.com:5000/nginx:alpine
```
- Are the new PODs created with the new images successfully running?
  ```bash
  k get pods
  ```
- Create a secret object with the credentials required to access the registry.
    Name: private-reg-cred
    Username: dock_user
    Password: dock_password
    Server: myprivateregistry.com:5000
    Email: dock_user@myprivateregistry.com
  ```
  k create secret docker-registry private-reg-cred --docker-username=dock_user --docker-password=dock_password --docker-server=myprivateregistry.com:5000 --docker-  email=dock_user@myprivateregistry.com
  ```
  - Configure the deployment to use credentials from the new secret to pull images from the private registry
    ```yaml
      apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    deployment.kubernetes.io/revision: "2"
  labels:
    app: web
  name: web
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - image: myprivateregistry.com:5000/nginx:alpine
        name: nginx
        resources: {}
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      securityContext: {}
      imagePullSecrets: 
        - name: private-reg-cred
    ```
  ## Kubesec

- What is the kubesec plugin used for?
    scanning kubernetes objects
  
- Install kubesec plugin on controlplane. Also make sure its binary is available globally to run.
- 
  ```bash
  wget https://github.com/controlplaneio/kubesec/releases/download/v2.13.0/kubesec_linux_amd64.tar.gz
  tar -xvf  kubesec_linux_amd64.tar.gz
  mv kubesec /usr/bin/
  ```
- What of the below input formats is NOT supported by kubesec?
  BASH
- We have a pod definition template /root/node.yaml on controlplane host. Scan this template using kubesec and save the report in /root/kubesec_report.json file on   controlplane host itself.
  ```
    kubesec scan node.yaml > kubesec_report.json
  ```
- Look into the report generated by the previous scan and identify the final status of the scan.
  failed
- kubesec scan failed for pod definition file /root/node.yaml . Fix the issues in this file as per the suggestions in the scan report and make sure that the final kubesec scan status is passed.
  In node.yaml template change privileged: true to privileged: false under securityContext:

## Trivy
- Install the trivy vulnerability scanner on controlplane host.
  ```bash
     curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v0.70.0
  ```
- Which of the following commands can be used to scan container images using trivy?
  ```
    trivy image
  ```
- Can we scan tarball archives using trivy ? yes
  We can use the --input option with the trivy image subcommand to scan for tar files.
- Which of the following artifacts cannot be scanned by trivy for security vulnerabilities?
  Network
- Which version of trivy have you installed on the controlplane node?
  ```
    trivy --version
  ```

  Important Note: From version 0.8.0 and newer, trivy images are scanned using the trivy image subcommand.
  However, in older versions, to carry out a scan use the syntax: trivy image_name. In these versions, the image sub-command will not work.

  For example, notice the differences in scanning the nginx image:
    Version: 0.16:
    trivy image nginx
    
    Version: 0.7.0 and older:
    trivy nginx

- Pull public.ecr.aws/docker/library/python:3.12.4 image on controlplane host and scan the same using trivy.
  Save the scan results in /root/python_12.txt file on controlplane host.
  ```
    crictl pull public.ecr.aws/docker/library/python:3.12.4
    # Scan the vulnerability
trivy image --output /root/python_12.txt public.ecr.aws/docker/library/python:3.12.4
  ```
- We have a docker image public.ecr.aws/docker/library/python:3.9-bullseye on controlplane host.
  Scan this image using trivy and filter out only high severity vulnerabilities in the report, finally save the report in /root/python.txt file on controlplane host itself
  ```
   trivy image --severity HIGH --output /root/python.txt public.ecr.aws/docker/library/python:3.9-bullseye
  ```
- There is a docker image file /root/alpine.tar on controlplane host, scan this archive file using trivy and save the results in /root/alpine.json file in json format.
  ```
    trivy image --input alpine.tar --format json --output /root/alpine.json
  ```
    
    
