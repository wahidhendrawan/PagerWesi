"""Provider registry for cloud security adapters."""

PROVIDERS = {
    "aws": "cloud.aws_harden",
    "azure": "cloud.azure_harden",
    "gcp": "cloud.gcp_harden",
}
