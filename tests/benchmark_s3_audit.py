import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from cloud.aws_harden import _check_bucket


def benchmark_bucket_checks(num_buckets=10, delay=0.1):
    print(f"Benchmarking {num_buckets} buckets with {delay}s simulated latency per API call")
    s3 = MagicMock()

    def delayed(value):
        def call(**_kwargs):
            time.sleep(delay)
            return value

        return call

    s3.get_bucket_acl.side_effect = delayed({"Grants": []})
    s3.get_bucket_policy_status.side_effect = delayed({"PolicyStatus": {"IsPublic": False}})
    s3.get_public_access_block.side_effect = delayed(
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
    )
    s3.get_bucket_encryption.side_effect = delayed(
        {"ServerSideEncryptionConfiguration": {"Rules": [{}]}}
    )
    s3.get_bucket_versioning.side_effect = delayed({"Status": "Enabled"})
    s3.get_bucket_logging.side_effect = delayed({"LoggingEnabled": {"TargetBucket": "logs"}})
    args = SimpleNamespace(mode="audit", control=[])

    started = time.perf_counter()
    for index in range(num_buckets):
        _check_bucket(s3, f"bucket-{index}", args)
    duration = time.perf_counter() - started
    print(f"Total time: {duration:.4f} seconds")
    return duration


if __name__ == "__main__":
    benchmark_bucket_checks()
