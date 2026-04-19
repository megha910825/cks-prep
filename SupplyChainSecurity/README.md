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
