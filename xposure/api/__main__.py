"""API server CLI entry point.

Run with: python -m xposure.api
"""

import argparse
import sys

from .server import run_server


def main():
    """Main entry point for API server."""
    parser = argparse.ArgumentParser(
        description='X-POSURE REST API Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python -m xposure.api                          # Start on 0.0.0.0:8080
  python -m xposure.api --port 9000              # Custom port
  python -m xposure.api --api-key "secret123"    # With authentication
  python -m xposure.api --db-path /data/app.db   # Custom database
        '''
    )

    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8080,
        help='Port to listen on (default: 8080)'
    )
    parser.add_argument(
        '--api-key',
        help='API key for authentication (optional)'
    )
    parser.add_argument(
        '--db-path',
        help='Path to SQLite database (default: ~/.xposure/xposure.db)'
    )

    args = parser.parse_args()

    print(r'''
    ██╗  ██╗      ██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗
    ╚██╗██╔╝      ██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
     ╚███╔╝ █████╗██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗
     ██╔██╗ ╚════╝██╔═══╝ ██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝
    ██╔╝ ██╗      ██║     ╚██████╔╝███████║╚██████╔╝██║  ██║███████╗
    ╚═╝  ╚═╝      ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

    [ API SERVER v4.0.0 ]
    ''')

    print(f'[*] Starting API server...')
    print(f'[*] Host: {args.host}')
    print(f'[*] Port: {args.port}')
    print(f'[*] Auth: {"Enabled" if args.api_key else "Disabled"}')
    print(f'[*] Database: {args.db_path or "~/.xposure/xposure.db"}')
    print()
    print(f'[+] API available at http://{args.host}:{args.port}')
    print(f'[+] Health check: http://{args.host}:{args.port}/health')
    print(f'[+] Documentation: http://{args.host}:{args.port}/api/v1')
    print()

    try:
        run_server(
            host=args.host,
            port=args.port,
            api_key=args.api_key,
            db_path=args.db_path,
        )
    except KeyboardInterrupt:
        print('\n[*] Shutting down...')
        sys.exit(0)


if __name__ == '__main__':
    main()
