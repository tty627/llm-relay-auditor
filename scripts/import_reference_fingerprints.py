import argparse
from pathlib import Path

from relay_auditor.config import Settings
from relay_auditor.database import Database
from relay_auditor.evidence import EvidenceStore
from relay_auditor.reference_import import import_reference_directory


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import tracked One Token fingerprint snapshots into Relay Auditor.",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("references/opentech-2026-08-20"),
    )
    parser.add_argument("--base-url", default="https://api.opentech.top/v1")
    parser.add_argument("--provider", default="opentech_snapshot")
    parser.add_argument("--reference-prefix", default="OpenTech 2026-08-20")
    parser.add_argument("--valid-days", type=int, default=14)
    parser.add_argument("--database-url")
    parser.add_argument("--evidence-dir", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    settings = Settings()
    database = Database(args.database_url or settings.database_url)
    evidence = EvidenceStore(args.evidence_dir or settings.evidence_dir)
    imported = import_reference_directory(
        args.source,
        database=database,
        evidence=evidence,
        base_url=args.base_url,
        provider=args.provider,
        reference_prefix=args.reference_prefix,
        valid_days=args.valid_days,
        extra_metadata={
            "comparison_report": "references/opentech-2026-08-20/REPORT.md",
        },
        per_reference_metadata={
            "key-a/gpt-5.6-sol.fingerprint.json": {
                "quality_flags": ["high_split_half_jsd"],
                "split_half_jsd": 0.278,
            },
            "key-b/gpt-5.3-codex-spark.fingerprint.json": {
                "quality_flags": ["high_split_half_jsd"],
                "split_half_jsd": 0.276,
            },
        },
    )
    for item in imported:
        print(f"{item.source_label}\t{item.model}\t{item.status}\tartifact={item.artifact_id}")
    print(f"Imported {len(imported)} reference fingerprints.")


if __name__ == "__main__":
    main()
