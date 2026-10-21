"""Command-line entry point for OctopusJar."""

import typer

app = typer.Typer(
    name="octopusjar",
    help="Security analysis for REST APIs you are authorized to assess.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """OctopusJar command group."""


if __name__ == "__main__":
    app()
