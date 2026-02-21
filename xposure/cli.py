"""X-POSURE command-line interface."""

import asyncio
import sys

import click
import yaml

from .__version__ import __version__
from .core.engine import XPosureEngine
from .ui.banners import BANNER_MAIN, BANNER_COMPACT
from .ui.colors import COLORS


def print_banner(compact: bool = False):
    """Print the X-POSURE banner."""
    banner = BANNER_COMPACT if compact else BANNER_MAIN
    print(banner)


def load_config_file(path: str = ".xposure.yaml") -> dict:
    """Load configuration from YAML file if it exists."""
    from pathlib import Path

    config_path = Path(path)
    if not config_path.exists():
        return {}

    try:
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)
            return data or {}
    except Exception:
        return {}


@click.group(invoke_without_command=True)
@click.option('--version', '-v', is_flag=True, help='Show version')
@click.option('--config', '-c', type=click.Path(), default='.xposure.yaml', help='Config file path')
@click.pass_context
def main(ctx, version, config):
    """
    X-POSURE — Shit your DevOps forgot.

    Attack surface reveal tool combining outside-in recon, inside-out
    container scanning, git history mining, and live credential verification.

    Examples:

        xposure scan example.com

        xposure scan example.com -rc --shodan-key XXXXX

        xposure scan --internal

        xposure scan --git /path/to/repo

        xposure scan --combined example.com -rc --git ./ --internal

        xposure verify findings.json

        xposure report findings.json --html
    """
    ctx.ensure_object(dict)

    if version:
        print(f"x-posure v{__version__}")
        sys.exit(0)

    # Load config file
    ctx.obj['config'] = load_config_file(config)

    # If no subcommand given, show help
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.argument('target', required=False)
@click.option('--github-token', '-g', envvar='GITHUB_TOKEN', help='GitHub token for dorking')
@click.option('--output', '-o', type=click.Path(), help='Output file (JSON)')
@click.option('--quiet', '-q', is_flag=True, help='Minimal output')
@click.option('--no-verify', is_flag=True, help='Skip active verification')
@click.option('--recursive-crawl', '-rc', is_flag=True, help='Recursive crawl with evasion')
@click.option('--crawl-depth', type=int, default=5, help='Max crawl depth (default: 5)')
@click.option('--crawl-max-pages', type=int, default=500, help='Max pages to crawl (default: 500)')
@click.option('--crawl-sleep', type=float, nargs=2, default=(1.0, 3.0), help='Min/max sleep between requests')
@click.option('--no-trufflehog', is_flag=True, help='Disable TruffleHog secrets scanning during crawl')
@click.option('--shodan-key', envvar='SHODAN_API_KEY', help='Shodan API key for infra mapping')
@click.option('--anthropic-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key for AI analysis')
@click.option('--internal', '-i', is_flag=True, help='Scan local container/server environment')
@click.option('--git', type=str, default=None, help='Scan git repo (path or URL)')
@click.option('--file', 'file_path', type=click.Path(exists=True), default=None, help='Scan local directory for secrets')
@click.option('--combined', is_flag=True, help='Run all scan modes together')
@click.option('--unmask', is_flag=True, help='Show raw credential values in output')
@click.option('--resume', type=str, default=None, help='Resume scan from state file')
@click.option('--sarif', type=click.Path(), default=None, help='Also output SARIF file')
@click.option('--html', type=click.Path(), default=None, help='Also output HTML report')
@click.pass_context
def scan(ctx, target, github_token, output, quiet, no_verify,
         recursive_crawl, crawl_depth, crawl_max_pages, crawl_sleep,
         no_trufflehog, shodan_key, anthropic_key,
         internal, git, file_path, combined, unmask, resume, sarif, html):
    """Scan a target for exposed credentials.

    \b
    Modes:
      xposure scan example.com              Standard external scan
      xposure scan example.com -rc          + recursive crawl
      xposure scan --internal               Internal container/server scan
      xposure scan --git /path/to/repo      Git history scan
      xposure scan --git https://...        Remote git scan
      xposure scan --file /path/to/dir      Scan local directory for secrets
      xposure scan --combined example.com   All modes together
    """
    file_config = ctx.obj.get('config', {})

    # Merge config file values with CLI (CLI takes precedence)
    target = target or file_config.get('target')
    if file_config.get('modes', {}).get('recursive_crawl') and not recursive_crawl:
        recursive_crawl = True
    if file_config.get('modes', {}).get('internal') and not internal:
        internal = True
    if file_config.get('modes', {}).get('git') and not git:
        git = file_config['modes']['git']

    keys_config = file_config.get('keys', {})
    shodan_key = shodan_key or keys_config.get('shodan')
    github_token = github_token or keys_config.get('github')
    anthropic_key = anthropic_key or keys_config.get('anthropic')

    # Require at least one scan mode
    if not target and not internal and not git and not file_path:
        click.echo("Error: Must provide a TARGET, --internal, --git, or --file.", err=True)
        click.echo("Try 'xposure scan --help' for help.")
        sys.exit(2)

    # Print banner
    if not quiet:
        print_banner(compact=False)

    # Create and run engine
    engine = XPosureEngine(
        target=target or 'internal',
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

    # Store extra scan modes for engine
    engine.scan_internal = internal or combined
    engine.scan_git = git
    engine.scan_file = file_path
    engine.unmask = unmask

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

        # SARIF output
        if sarif:
            from .output.sarif import write_sarif
            write_sarif(
                findings=engine.all_findings,
                output_path=sarif,
                target=target or 'internal',
            )
            if not quiet:
                print(f"SARIF report saved to {sarif}")

        # HTML output
        if html:
            from .output.html_report import write_html_report
            write_html_report(
                findings=engine.all_findings,
                stats=engine.stats,
                output_path=html,
                target=target or 'internal',
            )
            if not quiet:
                print(f"HTML report saved to {html}")

    except KeyboardInterrupt:
        print("\n[x-posure] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[x-posure] Error: {e}", file=sys.stderr)
        if not quiet:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.argument('findings_file', type=click.Path(exists=True))
@click.option('--quiet', '-q', is_flag=True, help='Minimal output')
@click.pass_context
def verify(ctx, findings_file, quiet):
    """Re-verify findings from a previous scan.

    \b
    Example:
      xposure verify findings.json
    """
    import json

    if not quiet:
        print_banner(compact=True)

    with open(findings_file, 'r') as f:
        data = json.load(f)

    findings_data = data.get('findings', data) if isinstance(data, dict) else data
    if not quiet:
        print(f"[verify] Loaded {len(findings_data)} findings from {findings_file}")
        print("[verify] Re-verification of exported findings is not yet fully implemented.")
        print("[verify] Use 'xposure scan' with the original target to re-scan.")


@main.command()
@click.argument('findings_file', type=click.Path(exists=True))
@click.option('--html', type=click.Path(), default=None, help='Output HTML report')
@click.option('--sarif', type=click.Path(), default=None, help='Output SARIF report')
@click.option('--json-out', type=click.Path(), default=None, help='Output JSON report')
@click.pass_context
def report(ctx, findings_file, html, sarif, json_out):
    """Generate reports from previous scan results.

    \b
    Examples:
      xposure report findings.json --html report.html
      xposure report findings.json --sarif results.sarif
    """
    import json

    print_banner(compact=True)

    with open(findings_file, 'r') as f:
        data = json.load(f)

    if not html and not sarif and not json_out:
        click.echo("Error: Must specify at least one output format (--html, --sarif, --json-out).", err=True)
        sys.exit(2)

    print(f"[report] Loaded data from {findings_file}")

    if html:
        print(f"[report] HTML report generation: {html}")

    if sarif:
        print(f"[report] SARIF report generation: {sarif}")

    if json_out:
        with open(json_out, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[report] JSON saved to {json_out}")


@main.command()
@click.argument('old_file', type=click.Path(exists=True))
@click.argument('new_file', type=click.Path(exists=True))
@click.pass_context
def diff(ctx, old_file, new_file):
    """Diff two scan results to find new/removed findings.

    \b
    Example:
      xposure diff old_findings.json new_findings.json
    """
    import json

    print_banner(compact=True)

    with open(old_file, 'r') as f:
        old_data = json.load(f)
    with open(new_file, 'r') as f:
        new_data = json.load(f)

    old_findings = old_data.get('findings', []) if isinstance(old_data, dict) else old_data
    new_findings = new_data.get('findings', []) if isinstance(new_data, dict) else new_data

    old_ids = {f.get('id', f.get('masked_value', '')) for f in old_findings}
    new_ids = {f.get('id', f.get('masked_value', '')) for f in new_findings}

    added = new_ids - old_ids
    removed = old_ids - new_ids
    unchanged = old_ids & new_ids

    print(f"\n[diff] Comparing {old_file} -> {new_file}")
    print(f"  Added:     {len(added)}")
    print(f"  Removed:   {len(removed)}")
    print(f"  Unchanged: {len(unchanged)}")

    if added:
        print("\n  New findings:")
        for fid in sorted(added):
            print(f"    + {fid}")

    if removed:
        print("\n  Removed findings:")
        for fid in sorted(removed):
            print(f"    - {fid}")


if __name__ == '__main__':
    main()
