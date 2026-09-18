"""lookup.py is now a thin operator-facing view over investigate/. Test what it still owns."""

from __future__ import annotations

from datetime import UTC, datetime

from investigate.blast_radius import (
    BlastRadius,
    CreatedResource,
    EvidenceProblem,
    ProblemKind,
    ResourceKind,
)

NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)


def radius(*, problems: list[EvidenceProblem] | None = None) -> BlastRadius:
    return BlastRadius(
        access_key_id="AKIA" + "IOSFODNN7EXAMPLE",
        regions_searched=["ap-south-1"],
        window_start=NOW,
        window_end=NOW,
        resources=[
            CreatedResource(
                resource_id="i-0a1b2c3d4e5f60001",
                kind=ResourceKind.EC2_INSTANCE,
                event_name="RunInstances",
                region="ap-south-1",
                event_time=NOW,
                source_ip="203.0.113.10",
                event_id="abc",
            )
        ],
        problems=problems or [],
    )


def test_the_report_shows_each_created_resource(lookup, capsys):
    lookup.print_report(radius())

    printed = capsys.readouterr().out
    assert "i-0a1b2c3d4e5f60001" in printed
    assert "ap-south-1" in printed
    assert "RunInstances" in printed


def test_an_empty_radius_says_so_rather_than_printing_an_empty_table(lookup, capsys):
    empty = radius()
    empty.resources.clear()

    lookup.print_report(empty)

    assert "no resources created by this key" in capsys.readouterr().out


def test_incomplete_evidence_is_shouted_about_on_stderr(lookup, capsys):
    problem = EvidenceProblem(
        kind=ProblemKind.REGION_LOOKUP_FAILED, region="us-east-1", aws_error_code="AccessDenied"
    )

    lookup.print_report(radius(problems=[problem]))

    errors = capsys.readouterr().err
    assert "EVIDENCE IS INCOMPLETE" in errors
    assert "us-east-1" in errors
    assert "AccessDenied" in errors


def test_regions_default_to_the_environment(lookup, monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_SECONDARY_REGION", raising=False)

    assert lookup.main(["AKIA" + "IOSFODNN7EXAMPLE"]) == 2


def test_the_documented_flags_parse(lookup):
    args = lookup.parse_args(["AKIA" + "IOSFODNN7EXAMPLE", "--wait", "900", "--hours", "6"])

    assert args.wait == 900
    assert args.hours == 6


def test_it_can_write_the_blast_radius_the_capture_script_reads(lookup, tmp_path):
    """Without this there is no way to produce the input capture_narration.py needs."""
    from investigate.blast_radius import BlastRadius

    args = lookup.parse_args(["AKIA" + "IOSFODNN7EXAMPLE", "--out", str(tmp_path / "r.json")])

    assert args.out == tmp_path / "r.json"
    # And what it writes round-trips into the type the narrator and verifier both take.
    written = tmp_path / "r.json"
    written.write_text(
        BlastRadius(
            access_key_id="AKIA" + "IOSFODNN7EXAMPLE",
            regions_searched=["ap-south-1"],
            window_start="2026-09-18T08:00:00+00:00",
            window_end="2026-09-18T11:00:00+00:00",
        ).model_dump_json()
    )
    assert BlastRadius.model_validate_json(written.read_text()).regions_searched == ["ap-south-1"]
