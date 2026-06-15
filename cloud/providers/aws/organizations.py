from __future__ import annotations


def discover_active_accounts(session) -> list[str]:
    paginator = session.client("organizations").get_paginator("list_accounts")
    return [
        account["Id"]
        for page in paginator.paginate()
        for account in page.get("Accounts", [])
        if account.get("State", account.get("Status")) == "ACTIVE"
    ]


def assumed_session(base_session, account_id: str, role_name: str, external_id: str | None = None):
    import boto3

    request = {
        "RoleArn": f"arn:aws:iam::{account_id}:role/{role_name}",
        "RoleSessionName": "automation-hardening-audit",
    }
    if external_id:
        request["ExternalId"] = external_id
    credentials = base_session.client("sts").assume_role(**request)["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=base_session.region_name,
    )


def session_in_region(session, region: str):
    import boto3

    credentials = session.get_credentials().get_frozen_credentials()
    return boto3.Session(
        aws_access_key_id=credentials.access_key,
        aws_secret_access_key=credentials.secret_key,
        aws_session_token=credentials.token,
        region_name=region,
    )
