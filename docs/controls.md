# Control Catalog

The benchmark field currently identifies `Project baseline v1`. Control mappings should be pinned
to an exact licensed benchmark version before this project is used for formal compliance evidence.

| ID | Target | Intent | Apply behavior |
|---|---|---|---|
| AWS-ORG-001 | AWS account | Confirm each organization member account is assessable | Report only |
| AWS-S3-001 | AWS account | Block public S3 access at account level | Enables all four settings |
| AWS-S3-002 | S3 bucket | Reject public ACL grants | Report only |
| AWS-S3-003 | S3 bucket | Reject public bucket policies | Report only |
| AWS-S3-004 | S3 bucket | Block public access at bucket level | Enables all four settings |
| AWS-S3-005 | S3 bucket | Enable default encryption | Enables SSE-S3 |
| AWS-S3-006 | S3 bucket | Enable versioning | Enables versioning |
| AWS-S3-007 | S3 bucket | Configure server access logging | Report only |
| AWS-IAM-001 | AWS account | Require root-user MFA | Report only |
| AWS-CT-001 | AWS account | Keep a multi-region CloudTrail trail logging | Report only |
| AWS-CONFIG-001 | AWS region | Enable AWS Config recording | Report only |
| AWS-GD-001 | AWS region | Enable GuardDuty | Report only |
| AWS-SH-001 | AWS region | Enable Security Hub | Report only |
| AWS-EC2-001 | AWS region | Remove rules from default security groups | Report only |
| AWS-KMS-001 | AWS region | Rotate eligible customer-managed keys | Report only |
| AZURE-IAM-001 | Azure | Discover assessable subscriptions | Report only |
| AZURE-STORAGE-001 | Azure | Enforce HTTPS and modern TLS for Storage | Report only |
| AZURE-STORAGE-002 | Azure | Default Storage network access to deny | Report only |
| AZURE-NET-001 | Azure | Restrict internet-exposed administrative ports | Report only |
| AZURE-SEC-001 | Azure | Enable Defender for Cloud plans | Report only |
| AZURE-LOG-001 | Azure | Export subscription activity logs | Report only |
| GCP-IAM-001 | GCP | Discover assessable projects | Report only |
| GCP-STORAGE-001 | GCP | Reject public Cloud Storage IAM | Report only |
| GCP-STORAGE-002 | GCP | Enable uniform bucket-level access | Report only |
| GCP-NET-001 | GCP | Restrict internet-exposed administrative ports | Report only |
| GCP-LOG-001 | GCP | Configure centralized logging sinks | Report only |
| GCP-SEC-001 | GCP | Review Security Command Center posture | Manual |
| LINUX-FW-001 | Linux | Enable a host firewall | Enables UFW/firewalld |
| LINUX-SSH-001 | Linux | Disable SSH root login | Updates and validates sshd config |
| LINUX-SSH-002 | Linux | Disable SSH empty passwords | Updates and validates sshd config |
| LINUX-PATCH-001 | Linux | Apply available package updates | Updates packages |
| MACOS-FW-001 | macOS | Enable firewall and stealth mode | Applies setting |
| MACOS-GK-001 | macOS | Enable Gatekeeper | Applies setting |
| MACOS-PATCH-001 | macOS | Enable scheduled update checks | Applies setting |
| MACOS-AUTH-001 | macOS | Disable guest account | Applies setting |
| MACOS-DISK-001 | macOS | Enable FileVault | Manual due to key escrow requirements |
| WINDOWS-FW-001 | Windows | Enable firewall profiles | Applies setting |
| WINDOWS-SMB-001 | Windows | Disable SMBv1 | Disables optional feature |
| WINDOWS-AUTH-001 | Windows | Disable RID-501 guest account | Applies setting |
| WINDOWS-AUDIT-001 | Windows | Enable logon and process auditing | Applies setting |

## Known Gaps

- AWS checks support named profiles, Organizations account discovery, role assumption, and
  multi-region assessment. Member-account failures are isolated and reported per account.
- AWS RDS and organization-wide aggregation controls are not yet implemented.
- Azure and GCP cover high-value storage, network, monitoring, and logging baselines but do not yet
  represent complete provider benchmarks.
- OS checks cover a high-value baseline, not a complete workstation/server benchmark.
- Linux rollback restores SSH configuration only; package and firewall state require platform-native
  recovery procedures.

Framework relationships are maintained in [compliance-mapping.json](compliance-mapping.json).
They are informative and must be validated against the exact licensed benchmark and organizational
scope before being used as compliance evidence.
