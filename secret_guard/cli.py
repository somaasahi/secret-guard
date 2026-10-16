"""Command-line entry point."""

import argparse
import json
import os
import sys
import time

from . import __version__, hooks
from .audit import run_audit
from .config import load_config
from .gitutil import (GitError, changed_files, parse_added_lines, range_diff,
                      repo_root, staged_diff)
from .scanner import read_text_file, scan_filename, scan_lines

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

SUGGESTED_FIX = (
    "  Fix: remove the secret and load it at runtime from AWS SSM Parameter Store,\n"
    "       e.g. ssm.get_parameter(Name='/myapp/prod/<name>', WithDecryption=True)\n"
    "  False positive? Append '# secretguard:ignore' to the line, or add the\n"
    "       fingerprint (or a path glob) to .secretguard-allow"
)


def _print_findings(findings, header, stream=sys.stderr):
    print(f"[secret-guard] {header}: {len(findings)} potential secret(s) found\n", file=stream)
    for f in findings:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        print(f"  {loc:<36} {f.description:<38} {f.masked}", file=stream)
        if f.fingerprint:
            print(f"  {'':<36} {f.fingerprint}", file=stream)
    print("", file=stream)


def _emit(findings, args, elapsed_ms, header):
    if args.format == "json":
        json.dump({"findings": [f.to_dict() for f in findings], "elapsed_ms": round(elapsed_ms, 2)},
                  sys.stdout, indent=2)
        print()
    elif findings:
        _print_findings(findings, header)
        print(SUGGESTED_FIX, file=sys.stderr)
    elif not args.quiet:
        print(f"[secret-guard] No secrets detected ({elapsed_ms:.1f} ms)", file=sys.stderr)
    return EXIT_FINDINGS if findings else EXIT_CLEAN


def cmd_scan(args):
    start = time.perf_counter()
    if args.files:
        cfg = load_config(os.getcwd())
        findings = []
        for path in args.files:
            targets = [path]
            if os.path.isdir(path):
                targets = [os.path.join(d, n) for d, _, ns in os.walk(path) for n in ns]
            for target in targets:
                findings.extend(scan_filename(target, cfg))
                lines = read_text_file(target)
                if lines is not None:
                    findings.extend(scan_lines(target, enumerate(lines, start=1), cfg))
        header = "Scan"
    else:
        root = repo_root()
        os.chdir(root)
        cfg = load_config(root)
        if args.since:
            diff, names = range_diff(args.since), changed_files([f"{args.since}...HEAD"])
            header = f"Changes since {args.since}"
        else:
            diff, names = staged_diff(), changed_files(["--cached"])
            header = "Commit blocked"
        findings = []
        for path in names:
            findings.extend(scan_filename(path, cfg))
        for path, lines in parse_added_lines(diff).items():
            findings.extend(scan_lines(path, lines, cfg))
    elapsed = (time.perf_counter() - start) * 1000
    return _emit(findings, args, elapsed, header)


def cmd_audit(args):
    root = os.path.abspath(args.path)
    report = run_audit(root, load_config(root))
    if args.format == "json":
        json.dump({
            "tracked": [f.to_dict() for f in report.tracked],
            "git_ignored": [f.to_dict() for f in report.git_ignored],
            "agent_read_protected": report.agent_read_protected,
            "protected_by": report.protected_by,
            "aws_long_term_keys": report.aws_long_term_keys,
        }, sys.stdout, indent=2)
        print()
        return EXIT_FINDINGS if report.exposed else EXIT_CLEAN

    out = sys.stdout
    print(f"[secret-guard] Local exposure audit: {root}\n", file=out)
    if report.tracked:
        _print_findings(report.tracked, "Visible to Git AND AI agents", out)
    if report.git_ignored:
        _print_findings(report.git_ignored, "Hidden from Git but readable by AI agents", out)
    if not report.exposed:
        print("  No plaintext secrets found in the working tree.\n", file=out)

    print("  AI agent controls:", file=out)
    if report.protected_by:
        for rule in report.protected_by:
            print(f"    [partial] Claude Code deny rule -> {rule}", file=out)
        print("    Note: deny rules stop file tools and simple shell reads (cat, head), but not\n"
              "          indirect reads such as `grep -r` or a script; use the OS sandbox as well.", file=out)
    else:
        print("    [missing] No Claude Code permission rule denies reading .env files.", file=out)
    if report.aws_long_term_keys:
        print("    [warning] ~/.aws/credentials holds long-term IAM user keys; an agent with shell\n"
              "              access can call AWS (e.g. ssm get-parameter) with your permissions.", file=out)
    if report.exposed:
        print("\n  Recommendation: move these values to Parameter Store and grant read access\n"
              "  only to the application's IAM role, not to developer or agent credentials.", file=out)
    return EXIT_FINDINGS if report.exposed else EXIT_CLEAN


def cmd_install(args):
    path = hooks.install_global() if args.global_ else hooks.install_repo()
    scope = "all repositories (core.hooksPath)" if args.global_ else "this repository"
    print(f"[secret-guard] pre-commit hook installed for {scope}: {path}")
    return EXIT_CLEAN


def cmd_uninstall(args):
    print("[secret-guard] " + (hooks.uninstall_global() if args.global_ else hooks.uninstall_repo()))
    return EXIT_CLEAN


def build_parser():
    p = argparse.ArgumentParser(prog="secret-guard",
                                description="Block API keys and other secrets before they are committed.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan staged changes (default), a commit range, or files")
    s.add_argument("--since", metavar="REF", help="scan commits since REF (CI mode)")
    s.add_argument("--files", nargs="+", metavar="PATH", help="scan files or directories directly")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("audit", help="report secrets readable by AI coding agents in the working tree")
    a.add_argument("path", nargs="?", default=".")
    a.add_argument("--format", choices=["text", "json"], default="text")
    a.set_defaults(func=cmd_audit)

    for name, func in (("install", cmd_install), ("uninstall", cmd_uninstall)):
        i = sub.add_parser(name, help=f"{name} the pre-commit hook")
        i.add_argument("--global", dest="global_", action="store_true",
                       help="apply to every repository on this machine via core.hooksPath")
        i.set_defaults(func=func)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except GitError as exc:
        print(f"[secret-guard] git error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
