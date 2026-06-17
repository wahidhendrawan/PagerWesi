"""Provider registry for cloud security adapters."""

PROVIDERS = {
    "aws": "cloud.aws_harden",
    "azure": "cloud.azure_harden",
    "gcp": "cloud.gcp_harden",
    "k8s": "cloud.k8s_harden",
    "docker": "cloud.docker_cis",
    "secrets": "cloud.secrets_scanner",
    "terraform": "cloud.terraform_plan",
    "network": "cloud.network_scanner",
}
