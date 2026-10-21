"""Smoke tests for the CLI entry point."""

from typer.testing import CliRunner

from octopusjar.cli import app


def test_cli_shows_help() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "authorized to assess" in result.stdout
