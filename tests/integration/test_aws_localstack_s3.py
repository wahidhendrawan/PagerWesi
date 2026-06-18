import os
from types import SimpleNamespace

import pytest

from cloud.core import Status
from cloud.providers.aws.baseline import _check_bucket

pytestmark = pytest.mark.integration


def _options():
    return SimpleNamespace(control=["AWS-S3-002"], mode="audit", policy=None)


@pytest.mark.skipif(
    not os.getenv("LOCALSTACK_ENDPOINT"),
    reason="Set LOCALSTACK_ENDPOINT to run the optional LocalStack S3 integration test.",
)
def test_s3_public_access_block_contract_against_localstack():
    import boto3

    endpoint = os.environ["LOCALSTACK_ENDPOINT"]
    session = boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
    )
    s3 = session.client("s3", endpoint_url=endpoint)
    bucket = "pagerwesi-contract"
    try:
        s3.create_bucket(Bucket=bucket)
    except Exception:
        pass

    findings = _check_bucket(s3, bucket, _options())

    assert findings
    assert findings[0].control_id == "AWS-S3-002"
    assert findings[0].status in {Status.PASS, Status.FAIL, Status.ERROR}
