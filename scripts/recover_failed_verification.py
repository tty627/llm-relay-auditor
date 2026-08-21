import argparse
import asyncio
import json

from relay_auditor.recovery import recover_failed_verification


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recover a failed One Token verification from local fingerprint files.",
    )
    parser.add_argument("--failed-audit-id", required=True)
    parser.add_argument("--reference-artifact-id", required=True)
    return parser.parse_args()


async def async_main() -> int:
    args = parse_args()
    result = await recover_failed_verification(
        failed_audit_id=args.failed_audit_id,
        reference_artifact_id=args.reference_artifact_id,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    return asyncio.run(async_main())


if __name__ == "__main__":
    raise SystemExit(main())
