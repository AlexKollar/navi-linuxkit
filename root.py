"""Navi Linuxkit — entry point for the Apex chip runner.

The whole workbench lives in the app_linuxkit package beside this
file; this entry only adapts Apex's run(args) call to it. Apex passes
the words after the chip name as args.text, e.g.:

    perm 4755
"""

import shlex

try:
    from app_linuxkit.core import run_command
except ImportError:  # package-mode runner: the package rides beside us
    try:
        from .app_linuxkit.core import run_command
    except ImportError:
        run_command = None


def run(args):
    if run_command is None:
        print("error: the app_linuxkit package did not load with this chip.")
        return
    text = (getattr(args, "text", "") or "").strip()
    if not text:
        run_command([])
        return
    try:
        argv = shlex.split(text)
    except ValueError as exc:
        print("error: could not parse arguments: " + str(exc))
        return
    run_command(argv)
