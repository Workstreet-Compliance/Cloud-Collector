<p align="center">
  <img src="cloud_collector.png" alt="Cloud Collector" width="400">
</p>

<h1 align="center">Cloud Collector</h1>

<p align="center">
  <strong>Automated compliance evidence collection for AWS, GCP, and Azure</strong>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#evidence-categories">Evidence</a> •
  <a href="#frameworks">Frameworks</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/SOC_2-supported-purple?style=flat-square" alt="SOC 2">
  <img src="https://img.shields.io/badge/ISO_27001-supported-purple?style=flat-square" alt="ISO 27001">
  <img src="https://img.shields.io/badge/NIST_800--53-supported-purple?style=flat-square" alt="NIST">
  <img src="https://img.shields.io/badge/CIS-supported-purple?style=flat-square" alt="CIS">
</p>

---

Generate audit-ready evidence packages with automatic mapping to **SOC 2**, **ISO 27001**, **NIST 800-53**, and **CIS benchmarks**. Outputs structured JSON for GRC tools and formatted Markdown for auditor review.

## Installation

### Via skills.sh

```bash
npx skills add workstreet/compliance-skills
```

### Via pip

```bash
git clone https://github.com/workstreet/compliance-skills.git
cd compliance-skills
pip install -r requirements.txt
```

---

## Quick Start

### Using with Claude Code

Just ask naturally:

> *"Collect SOC 2 evidence from my AWS account"*

> *"Generate ISO 27001 audit documentation for GCP project xyz"*

> *"Check my Azure subscription for NIST 800-53 compliance"*

### Programmatic Usage

```python
from skills.evidence_collector.scripts.aws_evidence import AWSEvidenceCollector
from skills.evidence_collector.scripts.output_formatter import EvidenceFormatter

# Collect evidence
collector = AWSEvidenceCollector()
package = collector.collect_all()

# Export
EvidenceFormatter.save(package, "./evidence_output")  # JSON + Markdown
```

<details>
<summary><strong>GCP Example</strong></summary>

```python
from skills.evidence_collector.scripts.gcp_evidence import GCPEvidenceCollector

collector = GCPEvidenceCollector(project_id="my-project-id")
package = collector.collect_all()
```

</details>

<details>
<summary><strong>Azure Example</strong></summary>

```python
from skills.evidence_collector.scripts.azure_evidence import AzureEvidenceCollector

collector = AzureEvidenceCollector(subscription_id="your-subscription-id")
package = collector.collect_all()
```

</details>

---

## Evidence Categories

| Category | AWS | GCP | Azure |
|:---------|:----|:----|:------|
| **IAM** | Users, roles, policies, MFA | IAM bindings, service accounts | RBAC, custom roles |
| **Logging** | CloudTrail | Audit logs, sinks | Activity logs, diagnostics |
| **Storage** | S3 policies, encryption | GCS IAM, public access | Storage account security |
| **Security** | Security Hub findings | Security Command Center | Defender for Cloud |
| **Encryption** | KMS keys, rotation | Cloud KMS key rings | Key Vault config |
| **Network** | VPC, security groups, NACLs | Firewall rules, VPC | NSGs, VNets |

---

## Frameworks

<table width="100%">
<tr>
<td width="25%" align="center">
<h3>SOC 2</h3>
<p>Type II</p>
<code>CC6.x</code> <code>CC7.x</code>
</td>
<td width="25%" align="center">
<h3>ISO 27001</h3>
<p>2022</p>
<code>Annex A</code>
</td>
<td width="25%" align="center">
<h3>NIST</h3>
<p>800-53 Rev. 5</p>
<code>AC</code> <code>AU</code> <code>SC</code>
</td>
<td width="25%" align="center">
<h3>CIS</h3>
<p>Benchmarks v2.0</p>
<code>AWS</code> <code>GCP</code> <code>Azure</code>
</td>
</tr>
</table>

See [`references/control_mappings.md`](skills/evidence-collector/references/control_mappings.md) for complete mapping details.

---

## Prerequisites

<details>
<summary><strong>AWS Credentials</strong></summary>

```bash
# Option 1: AWS CLI
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
```

**Required permissions:**
- `iam:Get*`, `iam:List*`
- `cloudtrail:Describe*`, `cloudtrail:Get*`
- `s3:GetBucket*`, `s3:ListBucket`
- `securityhub:Get*`
- `kms:Describe*`, `kms:List*`
- `ec2:Describe*`

</details>

<details>
<summary><strong>GCP Credentials</strong></summary>

```bash
# Option 1: Application Default Credentials
gcloud auth application-default login

# Option 2: Service account
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
```

**Required roles:**
- `roles/iam.securityReviewer`
- `roles/logging.viewer`
- `roles/storage.objectViewer`
- `roles/securitycenter.findingsViewer`
- `roles/cloudkms.viewer`
- `roles/compute.viewer`

</details>

<details>
<summary><strong>Azure Credentials</strong></summary>

```bash
# Option 1: Azure CLI
az login

# Option 2: Service principal
export AZURE_CLIENT_ID=xxx
export AZURE_CLIENT_SECRET=xxx
export AZURE_TENANT_ID=xxx
```

**Required roles:**
- `Reader`
- `Security Reader`
- `Key Vault Reader`

</details>

---

## Output Formats

### JSON
Structured output for automated processing and GRC tool integration.

```json
{
  "metadata": {
    "collection_timestamp": "2024-01-15T10:30:00Z",
    "cloud_provider": "aws",
    "account_id": "123456789012"
  },
  "evidence": [...],
  "control_mappings": [...]
}
```

### Markdown
Human-readable reports with evidence grouped by category and control mapping tables—ready for auditor review.

---

## Project Structure

```
cloud-evidence-collector/
├── skills/
│   └── evidence-collector/
│       ├── SKILL.md                 # Claude instructions
│       ├── scripts/
│       │   ├── aws_evidence.py
│       │   ├── gcp_evidence.py
│       │   ├── azure_evidence.py
│       │   └── output_formatter.py
│       └── references/
│           ├── control_mappings.md
│           └── evidence_schema.json
├── .claude-plugin/plugin.json       # Claude plugin config
├── skills.json                      # skills.sh config
└── requirements.txt
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add evidence collectors or control mappings
4. Submit a pull request

---

## Security

This tool collects **read-only** evidence. It does not modify any cloud resources.

- Always use least-privilege credentials
- Review collected evidence before sharing externally
- For security issues, email **ryan@workstreet.com**

---

<p align="center">
  <sub>MIT License • Built for compliance teams who'd rather automate than audit manually</sub>
</p>
