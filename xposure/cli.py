"""X-POSURE command-line interface."""

import asyncio
import sys

import click

from .__version__ import __version__
from .core.engine import XPosureEngine
from .ui.banners import BANNER_MAIN, BANNER_COMPACT
from .ui.colors import COLORS


def print_banner(compact: bool = False):
    """Print the X-POSURE banner."""
    banner = BANNER_COMPACT if compact else BANNER_MAIN
    # Simple print for now - will use Rich colors later
    print(banner)


@click.command()
@click.argument('target', required=False)
@click.option('--github-token', '-g', envvar='GITHUB_TOKEN', help='GitHub token for dorking')
@click.option('--output', '-o', type=click.Path(), help='Output file (JSON)')
@click.option('--quiet', '-q', is_flag=True, help='Minimal output')
@click.option('--no-verify', is_flag=True, help='Skip active verification')
@click.option('--version', '-v', is_flag=True, help='Show version')
def main(target, github_token, output, quiet, no_verify, version):
    """
    X-POSURE — Shit your DevOps forgot.

    Scan a target domain for exposed credentials.

    Examples:

        xposure example.com

        xposure example.com --github-token ghp_xxx

        xposure example.com -o findings.json
    """
    if version:
        print(f"x-posure v{__version__}")
        sys.exit(0)

    # Require target if not showing version
    if not target:
        click.echo("Error: Missing argument 'TARGET'.", err=True)
        click.echo("Try 'xposure --help' for help.")
        sys.exit(2)

    # Print banner
    if not quiet:
        print_banner(compact=False)

    # Create and run engine
    engine = XPosureEngine(
        target=target,
        github_token=github_token,
        verify=not no_verify,
        output_file=output,
        quiet=quiet,
    )

    try:
        if quiet:
            asyncio.run(engine.run_quiet())
        else:
            asyncio.run(engine.run_with_dashboard())

        # Export results if requested
        if output:
            engine.export_json(output)
            if not quiet:
                print(f"\nResults saved to {output}")

    except KeyboardInterrupt:
        print("\n[x-posure] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[x-posure] Error: {e}", file=sys.stderr)
        if not quiet:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
