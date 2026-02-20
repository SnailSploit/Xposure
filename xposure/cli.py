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
@click.option('--recursive-crawl', '-rc', is_flag=True, help='Recursive crawl with evasion (UA rotation, fingerprints, sleep)')
@click.option('--crawl-depth', type=int, default=5, help='Max crawl depth (default: 5)')
@click.option('--crawl-max-pages', type=int, default=500, help='Max pages to crawl (default: 500)')
@click.option('--crawl-sleep', type=float, nargs=2, default=(1.0, 3.0), help='Min/max sleep between requests (default: 1.0 3.0)')
@click.option('--no-trufflehog', is_flag=True, help='Disable TruffleHog secrets scanning during crawl')
@click.option('--shodan-key', envvar='SHODAN_API_KEY', help='Shodan API key for infra mapping')
@click.option('--anthropic-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key for AI analysis')
def main(target, github_token, output, quiet, no_verify, version,
         recursive_crawl, crawl_depth, crawl_max_pages, crawl_sleep,
         no_trufflehog, shodan_key, anthropic_key):
    """
    X-POSURE — Shit your DevOps forgot.

    Scan a target domain for exposed credentials.

    Examples:

        xposure example.com

        xposure example.com --github-token ghp_xxx

        xposure example.com -o findings.json

        xposure example.com -rc --shodan-key XXXXX --anthropic-key sk-ant-XXX

        xposure example.com -rc --crawl-depth 10 --crawl-sleep 2.0 5.0
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
        recursive_crawl=recursive_crawl,
        crawl_depth=crawl_depth,
        crawl_max_pages=crawl_max_pages,
        crawl_min_sleep=crawl_sleep[0],
        crawl_max_sleep=crawl_sleep[1],
        use_trufflehog=not no_trufflehog,
        shodan_key=shodan_key,
        anthropic_key=anthropic_key,
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
