# Compliance Evidence Collector

Automated compliance evidence collection for AWS, GCP, and Azure cloud environments. Generates audit-ready evidence packages with automatic mapping to SOC 2, ISO 27001, NIST 800-53, and CIS benchmarks.

## Installation

### Via skills.sh (Recommended)

```bash
npx skills add workstreet/compliance-skills
```

### Via Claude Plugins

The skill is automatically discovered when you have Claude Code configured with plugin support.

### Manual Installation

Clone and install dependencies:

```bash
git clone https://github.com/workstreet/compliance-skills.git
cd compliance-skills
pip install -r requirements.txt
```

## Quick Start

### Collect AWS Evidence

```python
from skills.evidence_collector.scripts.aws_evidence import AWSEvidenceCollector
from skills.evidence_collector.scripts.output_formatter import EvidenceFormatter

collector = AWSEvidenceCollector()
package = collector.collect_all()

# Save as JSON and Markdown
EvidenceFormatter.save(package, "./evidence_output")
```

### Collect GCP Evidence

```python
from skills.evidence_collector.scripts.gcp_evidence import GCPEvidenceCollector

collector = GCPEvidenceCollector(project_id="my-project-id")
package = collector.collect_all()
```

### Collect Azure Evidence

```python
from skills.evidence_collector.scripts.azure_evidence import AzureEvidenceCollector

collector = AzureEvidenceCollector(subscription_id="your-subscription-id")
package = collector.collect_all()
```

### Using with Claude Code

Simply ask Claude to collect compliance evidence:

> "Collect SOC 2 evidence from my AWS account"

> "Generate ISO 27001 audit documentation for GCP project xyz"

> "Check my Azure subscription for NIST 800-53 compliance evidence"

## Evidence Categories

| Category | AWS | GCP | Azure |
|----------|-----|-----|-------|
| **IAM** | Users, roles, policies, MFA | IAM bindings, service accounts | RBAC assignments, custom roles |
| **Logging** | CloudTrail configuration | Audit logs, log sinks | Activity logs, diagnostic settings |
| **Storage** | S3 bucket policies, encryption | GCS IAM, public access | Storage account security |
| **Security** | Security Hub findings | Security Command Center | Defender for Cloud |
| **Encryption** | KMS keys, rotation | Cloud KMS key rings | Key Vault configuration |
| **Network** | VPC, security groups, NACLs | Firewall rules, VPC | NSGs, VNets, watchers |

## Supported Compliance Frameworks

- **SOC 2 Type II** - Common Criteria (CC) series
- **ISO 27001:2022** - Annex A controls
- **NIST 800-53 Rev. 5** - Security and privacy controls
- **CIS Benchmarks** - Cloud-specific benchmarks (AWS, GCP, Azure)

## Prerequisites

### AWS

```bash
# Configure credentials
aws configure

# Or use environment variables
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
```

Required permissions:
- `iam:Get*`, `iam:List*`
- `cloudtrail:Describe*`, `cloudtrail:Get*`
- `s3:GetBucket*`, `s3:ListBucket`
- `securityhub:Get*`
- `kms:Describe*`, `kms:List*`
- `ec2:Describe*`

### GCP

```bash
# Configure Application Default Credentials
gcloud auth application-default login

# Or use service account
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
```

Required roles:
- `roles/iam.securityReviewer`
- `roles/logging.viewer`
- `roles/storage.objectViewer`
- `roles/securitycenter.findingsViewer`
- `roles/cloudkms.viewer`
- `roles/compute.viewer`

### Azure

```bash
# Login via Azure CLI
az login

# Or use service principal
export AZURE_CLIENT_ID=xxx
export AZURE_CLIENT_SECRET=xxx
export AZURE_TENANT_ID=xxx
```

Required roles:
- `Reader`
- `Security Reader`
- `Key Vault Reader`

## Output Formats

### JSON

Structured output following the evidence schema. Ideal for automated processing and GRC tool integration.

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

Human-readable report with evidence grouped by category and control mapping tables. Ready for auditor review.

## Project Structure

```
cloud-evidence-collector/
├── skills/
│   └── evidence-collector/
│       ├── SKILL.md                    # Claude skill instructions
│       ├── scripts/
│       │   ├── aws_evidence.py         # AWS collector
│       │   ├── gcp_evidence.py         # GCP collector
│       │   ├── azure_evidence.py       # Azure collector
│       │   └── output_formatter.py     # Output formatting
│       └── references/
│           ├── control_mappings.md     # Framework mappings
│           └── evidence_schema.json    # JSON schema
├── .claude-plugin/
│   └── plugin.json                     # Claude plugin config
├── skills.json                         # skills.sh config
├── requirements.txt                    # Python dependencies
└── README.md
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your evidence collectors or control mappings
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security

This tool collects read-only evidence from cloud providers. It does not modify any resources. Always use least-privilege credentials and review collected evidence before sharing with external parties.

For security issues, please email security@workstreet.co instead of opening a public issue.
