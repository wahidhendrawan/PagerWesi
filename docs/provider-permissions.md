# Provider Permissions

Use read-only permissions for audit mode. Grant mutation permissions only to the identity that runs
`--mode apply`.

## AWS Audit

Minimum audit permissions should cover these read APIs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ListAnalyzers",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "config:DescribeConfigurationAggregators",
        "config:DescribeConfigurationRecorderStatus",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:GetEbsEncryptionByDefault",
        "guardduty:ListDetectors",
        "guardduty:ListOrganizationAdminAccounts",
        "iam:GetAccountSummary",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListKeys",
        "rds:DescribeDBInstances",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:ListAllMyBuckets",
        "securityhub:DescribeHub",
        "securityhub:ListOrganizationAdminAccounts",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

AWS apply mode needs additional permissions for the controls being remediated:

```json
{
  "Effect": "Allow",
  "Action": [
    "access-analyzer:CreateAnalyzer",
    "ec2:CreateFlowLogs",
    "ec2:EnableEbsEncryptionByDefault",
    "s3:PutAccountPublicAccessBlock",
    "s3:PutBucketEncryption",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutBucketVersioning"
  ],
  "Resource": "*"
}
```

## Azure Audit

Use Azure Reader plus targeted reader roles where needed:

- Reader at subscription scope
- Storage Account Reader
- Key Vault Reader
- SQL Server Reader
- Network Reader
- Security Reader
- Monitoring Reader

## GCP Audit

Use project-level or organization-level roles scoped to the resources being audited:

- `roles/viewer`
- `roles/storage.viewer`
- `roles/compute.networkViewer`
- `roles/logging.viewer`
- `roles/iam.serviceAccountViewer`
- `roles/cloudkms.viewer`
- Permission to call `resourcemanager.projects.getIamPolicy`

