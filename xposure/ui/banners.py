"""X-POSURE ASCII art banners."""

from ..__version__ import __version__

BANNER_MAIN = f"""
\033[91m
 ██╗  ██╗       ██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗
 ╚██╗██╔╝       ██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
  ╚███╔╝  █████╗██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗  
  ██╔██╗  ╚════╝██╔═══╝ ██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝  
 ██╔╝ ██╗       ██║     ╚██████╔╝███████║╚██████╔╝██║  ██║███████╗
 ╚═╝  ╚═╝       ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

 V.{__version__} // For Shit Your DevOps Forgot.
 by SnailSploit <3
\033[0m"""

BANNER_BLOCKY = f"""
\033[91m
 ▀▄▀ ▄▄   █▀█ █▀█ █▀ █ █ █▀█ █▀▀
 █ █ ▀▀   █▀▀ █▄█ ▄█ █▄█ █▀▄ ██▄

 V.{__version__} // For Shit Your DevOps Forgot.
 by SnailSploit <3
\033[0m"""

BANNER_COMPACT = f"""
\033[91m░▒▓█ X-POSURE █▓▒░\033[0m  v{__version__}
\033[91m>\033[0m For Shit Your DevOps Forgot.                      \033[91m[ SnailSploit <3 ]\033[0m
"""

BANNER_FINDING = """
\033[91m░▒▓█ X-POSURE █▓▒░\033[0m

        ██╗  ██╗      \033[91mfound something.\033[0m
        ╚██╗██╔╝
   \033[91m▓▓▓▓▓\033[0m ╚███╔╝ \033[91m▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m
   \033[91m▓▓▓▓▓\033[0m ██╔██╗ \033[91m▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m
        ██╔╝ ██╗
        ╚═╝  ╚═╝      \033[91mthey don't know yet.\033[0m
"""

BANNER_COMPLETE = """
\033[91m░▒▓█ X-POSURE █▓▒░\033[0m

        ██╗  ██╗      \033[91meverything leaks.\033[0m
        ╚██╗██╔╝
         ╚███╔╝       \033[91mthey just don't know it yet.\033[0m
         ██╔██╗
        ██╔╝ ██╗
        ╚═╝  ╚═╝
                                             \033[91m[ SnailSploit <3 ]\033[0m
"""


def get_banner(banner_type: str = "main") -> str:
    """Get banner by type."""
    banners = {
        "main": BANNER_MAIN,
        "blocky": BANNER_BLOCKY,
        "compact": BANNER_COMPACT,
        "finding": BANNER_FINDING,
        "complete": BANNER_COMPLETE,
    }
    return banners.get(banner_type, BANNER_MAIN)
