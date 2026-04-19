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
-
