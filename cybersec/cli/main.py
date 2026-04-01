import click

from cybersec.cli.scan import SCAN_GROUP
from cybersec.cli.tools import TOOLS_GROUP


@click.group()
@click.version_option(version="1.0.0")
@click.option("--debug", is_flag=True, help="Show full tracebacks on errors")
def cli(debug: bool) -> None:
    """CyberSec — Network security scanner and analysis toolkit."""
    if debug:
        import os
        os.environ["CYBERSEC_DEBUG"] = "1"


cli.add_command(SCAN_GROUP)
cli.add_command(TOOLS_GROUP)


if __name__ == "__main__":
    cli()
