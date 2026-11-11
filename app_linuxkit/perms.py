"""Permission math: numeric <-> symbolic, umask results, special bits.

Pure bit arithmetic, no I/O. The model every Linux admin carries:

    mode = [special][owner][group][other], each class = r(4) w(2) x(1)
    special = setuid(4) setgid(2) sticky(1), rendered s/s/t in the
    execute position of its class (capital when the class has no x).

A newly created file starts life asking for 0o666 and a directory
for 0o777; the umask only ever SUBTRACTS from those asks.
"""

SPECIAL_BITS = (0o4000, 0o2000, 0o1000)          # setuid, setgid, sticky
SPECIAL_LETTERS = ("s", "s", "t")
CLASS_NAMES = ("owner (u)", "group (g)", "other (o)")
CLASS_BITS = ((0o400, 0o200, 0o100),             # owner rwx
              (0o040, 0o020, 0o010),             # group rwx
              (0o004, 0o002, 0o001))             # other rwx


def numeric_to_symbolic(mode):
    """0o4755 -> 'rwsr-xr-x'. mode is masked to the low 12 bits."""
    mode &= 0o7777
    chars = []
    for idx in range(3):
        r, w, x = CLASS_BITS[idx]
        chars.append("r" if mode & r else "-")
        chars.append("w" if mode & w else "-")
        has_x = bool(mode & x)
        if mode & SPECIAL_BITS[idx]:
            letter = SPECIAL_LETTERS[idx]
            chars.append(letter if has_x else letter.upper())
        else:
            chars.append("x" if has_x else "-")
    return "".join(chars)


def symbolic_to_numeric(sym):
    """'rwsr-xr-x' -> 0o4755. Raises ValueError on anything malformed."""
    if len(sym) != 9:
        raise ValueError("a symbolic mode is exactly 9 characters "
                         "(rwxrwxrwx), got %d" % len(sym))
    mode = 0
    for idx in range(3):
        r, w, x = CLASS_BITS[idx]
        c_r, c_w, c_x = sym[idx * 3: idx * 3 + 3]
        if c_r == "r":
            mode |= r
        elif c_r != "-":
            raise ValueError("position %d must be 'r' or '-', got %r"
                             % (idx * 3 + 1, c_r))
        if c_w == "w":
            mode |= w
        elif c_w != "-":
            raise ValueError("position %d must be 'w' or '-', got %r"
                             % (idx * 3 + 2, c_w))
        letter = SPECIAL_LETTERS[idx]
        if c_x == "x":
            mode |= x
        elif c_x == "-":
            pass
        elif c_x == letter:
            mode |= x | SPECIAL_BITS[idx]
        elif c_x == letter.upper():
            mode |= SPECIAL_BITS[idx]
        else:
            raise ValueError("position %d must be 'x', '-', %r or %r, got %r"
                             % (idx * 3 + 3, letter, letter.upper(), c_x))
    return mode


def parse_mode_text(text):
    """Accept '755', '0755', '4755', 'rwxr-xr-x', or the 10-character
    ls form '-rwxr-xr-x' / 'drwxr-xr-x'. Returns (mode_int, kind_note)
    where kind_note names the ls file-type letter if one was given,
    else None. Raises ValueError with a plain-words reason."""
    text = text.strip()
    if not text:
        raise ValueError("nothing to read — give a mode like 755, 4755, "
                         "or rwxr-xr-x")
    if all(c in "01234567" for c in text) and len(text) in (3, 4):
        return int(text, 8), None
    kind = None
    sym = text
    if len(text) == 10 and text[0] in "-dlbcps":
        kind = text[0]
        sym = text[1:]
    if len(sym) == 9:
        return symbolic_to_numeric(sym), kind
    raise ValueError("%r is neither an octal mode (3-4 digits, 0-7) nor "
                     "a symbolic one (9 letters like rwxr-xr-x)" % text)


_FILE_VERBS = {"r": "read the contents", "w": "modify the contents",
               "x": "run it as a program"}
_DIR_VERBS = {"r": "list the names inside",
              "w": "create, delete and rename entries inside "
                   "(only bites together with x)",
              "x": "enter it and reach the files inside"}


def breakdown_lines(mode):
    """Who-can-do-what lines for a mode, file vs directory meaning."""
    lines = []
    for idx in range(3):
        sym = numeric_to_symbolic(mode)[idx * 3: idx * 3 + 3]
        # Held bits come from the MODE, not the letters: an 's' in the
        # execute position means x is held, though no 'x' is printed.
        held = [letter for bit, letter in zip(CLASS_BITS[idx], "rwx")
                if mode & bit]
        special = ""
        if mode & SPECIAL_BITS[idx]:
            special = " +%s" % ("setuid" if idx == 0 else
                                "setgid" if idx == 1 else "sticky")
        lines.append("  %-10s %s%s" % (CLASS_NAMES[idx], sym, special))
        if held:
            fv = ", ".join(_FILE_VERBS[c] for c in held)
            dv = ", ".join(_DIR_VERBS[c] for c in held)
            lines.append("             file: %s" % fv)
            lines.append("             dir:  %s" % dv)
        else:
            lines.append("             no access")
    return lines


def specials_lines(mode):
    """Explain whichever special bits a mode carries (or none)."""
    found = []
    if mode & 0o4000:
        found.append(
            "  setuid (4---): a program runs with its OWNER's privileges, "
            "not the caller's.\n"
            "    Classic example: /usr/bin/passwd is root-owned and setuid, "
            "so you can update\n"
            "    your own line in root-owned /etc/shadow. That narrow magic "
            "is exactly why\n"
            "    setuid-root binaries are audited (find / -perm -4000). The "
            "kernel ignores\n"
            "    setuid on shell scripts — only real binaries get it.")
    if mode & 0o2000:
        found.append(
            "  setgid (2---): on a program, it runs with the file's GROUP. "
            "On a DIRECTORY\n"
            "    it is the shared-folder switch: new files inside inherit "
            "the directory's\n"
            "    group instead of the creator's primary group.")
    if mode & 0o1000:
        found.append(
            "  sticky (1---): on a shared directory, only a file's OWNER "
            "(or root) can\n"
            "    delete or rename it, even though everyone can write there.\n"
            "    Classic example: /tmp is 1777 (drwxrwxrwt) — world-writable "
            "AND safe to\n"
            "    share because of that t. On a plain file the bit is a "
            "museum piece.")
    return found


def umask_apply(umask):
    """(file_mode, dir_mode) a create gets under this umask."""
    umask &= 0o777
    return (0o666 & ~umask) & 0o777, (0o777 & ~umask) & 0o777


def render_perm(text):
    """Full `perm <input>` output. Raises ValueError on bad input."""
    mode, kind = parse_mode_text(text)
    out = []
    sym = numeric_to_symbolic(mode)
    head = "%s = %04o" % (sym, mode)
    if kind:
        head += "   (the leading %r in your input is the ls file-type " \
                "letter, not a permission)" % kind
    out.append(head)
    out.extend(breakdown_lines(mode))
    sp = specials_lines(mode)
    if sp:
        out.append("special bits:")
        out.extend(sp)
    else:
        out.append("special bits: none set (a leading 0 in the 4-digit "
                   "form). Try perm 4755, 2755, 1777 to see them.")
    return "\n".join(out)


def render_umask(text):
    """Full `perm umask <value>` output."""
    text = text.strip()
    if not text or not all(c in "01234567" for c in text) \
            or len(text) not in (3, 4):
        raise ValueError("a umask is 3-4 octal digits, like 022 or 027 — "
                         "got %r" % text)
    umask = int(text, 8) & 0o777
    f_mode, d_mode = umask_apply(umask)
    out = [
        "umask %03o — the mask only subtracts; nothing a program asks "
        "for is ever added." % umask,
        "  new files:       ask 0666, mask %03o -> %04o (%s)"
        % (umask, f_mode, numeric_to_symbolic(f_mode)),
        "  new directories: ask 0777, mask %03o -> %04o (%s)"
        % (umask, d_mode, numeric_to_symbolic(d_mode)),
        "Why the two asks differ: a directory without x is a locked "
        "room you cannot\n"
        "enter, so directories ask for everything. Regular files "
        "deliberately do NOT\n"
        "ask for x — a downloaded file should never arrive executable; "
        "chmod +x is\n"
        "a human decision. Common values: 022 (world-readable default), "
        "027 (group\n"
        "can read, others nothing), 077 (owner only — the paranoid "
        "setting).",
    ]
    return "\n".join(out)


SPECIALS_TEXT = """special bits — the leading octal digit (setuid 4, setgid 2, sticky 1):

  setuid: a program executes with the privileges of the file's OWNER.
    /usr/bin/passwd (4755, rwsr-xr-x) is the classic: root-owned, so
    any user can update their own /etc/shadow entry through it. The
    same bit on the wrong binary is a root shell waiting to happen —
    audit with: find / -xdev -perm -4000 -type f 2>/dev/null
    Ignored on shell scripts by the kernel.

  setgid: a program executes with the file's GROUP privileges.
    On a directory it changes inheritance instead: files created
    inside take the DIRECTORY's group (2770 on a team share is the
    standard recipe, with the sticky thinking from perm 1777).

  sticky: on a directory, write access no longer means delete access
    for other people's files — only the owner (or root) may delete
    or rename. /tmp at 1777 is the classic. Without it, a shared
    writable directory lets anyone delete anyone's work."""
