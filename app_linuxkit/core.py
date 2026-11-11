"""Navi Linuxkit command core: dispatcher, renderers, --test.

Grammar:
    linuxkit                     overview + what each verb does
    linuxkit cmd <name>          command reference (33 commands)
    linuxkit cmd                 the whole shelf, grouped
    linuxkit perm <mode>         permission math (755 / rwxr-xr-x / 4755)
    linuxkit perm umask <mask>   what a create gets under a umask
    linuxkit perm special        setuid/setgid/sticky, explained
    linuxkit harden <topic>      ssh | users | services | updates |
                                 logging | firewall
    linuxkit fhs [path]          the filesystem map, or one place in it
    linuxkit drill               today's 10-question self-check
    linuxkit --test              self-test

This chip executes nothing and reads nothing on the host. It is a
reference and a calculator: the text it prints is the product, and
the student runs (or doesn't run) the real commands himself.
"""

import datetime
import difflib

try:
    from . import harden, learn, perms, refdata
except ImportError:  # imported outside the package (should not happen)
    from app_linuxkit import harden, learn, perms, refdata

VERSION = "1.0.0"
USAGE = ("usage: linuxkit cmd <name> | linuxkit perm <mode> | "
         "linuxkit perm umask <mask> | linuxkit harden <topic> | "
         "linuxkit fhs [path] | linuxkit drill | linuxkit --test")

OVERVIEW = """Navi Linuxkit 1.0.0 — the Linux admin workbench.

Nothing here runs on your machine. Linuxkit is a reference, a
calculator and a drill sergeant: it explains, computes and quizzes,
and leaves the typing of real commands to you.

  cmd <name>    33 admin commands with the flags that matter, one
                example, and the trap (cmd alone lists them all)
  perm <mode>   permission math both ways — 755, rwxr-xr-x, 4755 —
                with a who-can-do-what breakdown
  perm umask <m>  what new files and directories actually get
  perm special  setuid, setgid, sticky — the leading digit, demystified
  harden <topic>  ordered hardening checklists with the why for each
                step: ssh, users, services, updates, logging, firewall
  fhs [path]    the filesystem hierarchy, explained by place
  drill         today's 10-question self-check, answers folded below
  --test        prove the math

Built for CIS 141/142 territory: fluency for someone who already
lives on Linux and wants the admin depth underneath it."""


# ---------------------------------------------------------------- cmd

def render_cmd(entry):
    out = ["%s — %s" % (entry["name"], entry["title"]),
           "  %s" % entry["usage"],
           "  flags that matter:"]
    for flag, note in entry["flags"]:
        out.append("    %-16s %s" % (flag, note))
    out.append("  example: %s" % entry["example"])
    out.append("  careful: %s" % entry["careful"])
    return "\n".join(out)


def cmd_command(argv):
    if not argv:
        out = ["the shelf — cmd <name> for any of these:"]
        for group, names in refdata.GROUPS:
            out.append("  %s: %s" % (group, ", ".join(names)))
        return "\n".join(out)
    name = argv[0].lower()
    entry = refdata.lookup(name)
    if entry is None:
        close = difflib.get_close_matches(
            name, list(refdata.COMMANDS.keys()), n=3, cutoff=0.6)
        hint = (" Did you mean: %s?" % ", ".join(close)) if close else ""
        return ("linuxkit doesn't carry a reference entry for %r.%s "
                "cmd alone lists the shelf." % (argv[0], hint))
    if entry["name"] != name:
        head = "(%s is an alias of %s)\n" % (name, entry["name"])
        return head + render_cmd(entry)
    return render_cmd(entry)


# ---------------------------------------------------------------- perm

def perm_command(argv):
    if not argv:
        return ("perm reads a mode either way, does umask math, and "
                "explains the special bits:\n"
                "  perm 755            numeric -> symbolic + breakdown\n"
                "  perm rwxr-xr-x      symbolic -> numeric + breakdown\n"
                "  perm 4755           the leading digit is setuid\n"
                "  perm umask 027      what new files/dirs actually get\n"
                "  perm special        setuid/setgid/sticky, explained")
    head = argv[0].lower()
    try:
        if head == "umask":
            if len(argv) < 2:
                return ("give the mask too: perm umask 022 (or 027, "
                        "077...)")
            return perms.render_umask(argv[1])
        if head == "special":
            return perms.SPECIALS_TEXT
        return perms.render_perm(argv[0])
    except ValueError as exc:
        return "perm can't read that: %s" % exc


# ---------------------------------------------------------------- harden

def harden_command(argv):
    if not argv:
        names = ", ".join(harden.topic_names())
        return ("hardening checklists, ordered, each step with its "
                "why:\n  harden <topic> — topics: %s" % names)
    rendered = harden.render_topic(argv[0])
    if rendered is None:
        return ("no hardening checklist called %r. Topics: %s"
                % (argv[0], ", ".join(harden.topic_names())))
    return rendered


# ---------------------------------------------------------------- fhs / drill

def fhs_command(argv):
    if not argv:
        return learn.render_fhs_overview()
    return learn.render_fhs(argv[0])


def drill_command(_argv):
    doy = datetime.date.today().timetuple().tm_yday
    return learn.render_drill(doy)


# ---------------------------------------------------------------- --test

def _selftest():
    checks = []

    def check(label, got, want):
        checks.append((label, got, want, got == want))

    check("755 symbolic", perms.numeric_to_symbolic(0o755), "rwxr-xr-x")
    check("640 symbolic", perms.numeric_to_symbolic(0o640), "rw-r-----")
    check("4755 symbolic (setuid)",
          perms.numeric_to_symbolic(0o4755), "rwsr-xr-x")
    check("2755 symbolic (setgid)",
          perms.numeric_to_symbolic(0o2755), "rwxr-sr-x")
    check("1777 symbolic (sticky)",
          perms.numeric_to_symbolic(0o1777), "rwxrwxrwt")
    check("000 symbolic", perms.numeric_to_symbolic(0), "---------")
    check("rwxr-xr-x numeric", perms.symbolic_to_numeric("rwxr-xr-x"),
          0o755)
    check("rwsr-xr-x numeric", perms.symbolic_to_numeric("rwsr-xr-x"),
          0o4755)
    check("rwxrwxrwt numeric", perms.symbolic_to_numeric("rwxrwxrwt"),
          0o1777)
    check("ls form -rwxr-xr-x", perms.parse_mode_text("-rwxr-xr-x")[0],
          0o755)
    check("ls form drwxr-xr-x kind",
          perms.parse_mode_text("drwxr-xr-x")[1], "d")
    for mode in (0o000, 0o644, 0o600, 0o777, 0o4755, 0o2750, 0o1755,
                 0o7777, 0o4640):
        check("round-trip %04o" % mode,
              perms.symbolic_to_numeric(perms.numeric_to_symbolic(mode)),
              mode)
    check("umask 022 file", perms.umask_apply(0o022)[0], 0o644)
    check("umask 022 dir", perms.umask_apply(0o022)[1], 0o755)
    check("umask 027 file", perms.umask_apply(0o027)[0], 0o640)
    check("umask 027 dir", perms.umask_apply(0o027)[1], 0o750)
    check("umask 077 file", perms.umask_apply(0o077)[0], 0o600)
    check("umask 077 dir", perms.umask_apply(0o077)[1], 0o700)
    for bad in ("888", "rwxrwxrwz", "75", "rwx", ""):
        try:
            perms.parse_mode_text(bad)
            check("reject %r" % bad, "accepted", "ValueError")
        except ValueError:
            check("reject %r" % bad, "ValueError", "ValueError")

    bad_cmds = []
    for name in refdata.COMMANDS:
        entry = refdata.COMMANDS[name]
        text = render_cmd(entry)
        if entry["name"] not in text or "careful:" not in text:
            bad_cmds.append(name)
    check("all %d ref entries render" % len(refdata.COMMANDS),
          bad_cmds, [])

    bad_topics = [t for t in harden.topic_names()
                  if harden.render_topic(t) is None]
    check("all %d harden topics render" % len(harden.TOPICS),
          bad_topics, [])

    matched, _entry, exact = learn.resolve_fhs("/var/lib/dpkg")
    check("fhs fallback /var/lib/dpkg", (matched, exact), ("/var", False))
    matched, _entry, exact = learn.resolve_fhs("/var/log")
    check("fhs exact /var/log", (matched, exact), ("/var/log", True))
    matched, _entry, exact = learn.resolve_fhs("/nowhere/at/all")
    check("fhs floor is /", matched, "/")

    check("drill pick size", len(learn.drill_pick(100)), 10)
    check("drill deterministic", learn.drill_pick(100),
          learn.drill_pick(100))
    check("drill rotates by day",
          learn.drill_pick(100) != learn.drill_pick(101), True)
    check("drill wraps year-end", len(learn.drill_pick(366)), 10)

    lines = []
    failed = 0
    for label, got, want, ok in checks:
        lines.append("PASS %s" % label if ok else
                     "FAIL %s: got %r, want %r" % (label, got, want))
        if not ok:
            failed += 1
    lines.append("self-test: %d/%d passed" % (len(checks) - failed,
                                              len(checks)))
    return "\n".join(lines)


# ---------------------------------------------------------------- dispatch

def run_command(argv):
    if not argv:
        print(OVERVIEW)
        return
    head = argv[0].lower()
    rest = argv[1:]
    if head in ("--test", "-test", "test"):
        print(_selftest())
    elif head in ("help", "--help", "-h"):
        print(OVERVIEW)
        print("")
        print(USAGE)
    elif head == "cmd":
        print(cmd_command(rest))
    elif head in ("perm", "perms"):
        print(perm_command(rest))
    elif head == "harden":
        print(harden_command(rest))
    elif head == "fhs":
        print(fhs_command(rest))
    elif head == "drill":
        print(drill_command(rest))
    else:
        print("linuxkit doesn't know %r. %s" % (argv[0], USAGE))
