"""The FHS map and the self-check drill.

FHS: each entry is (title, body) — what lives there, and the admin
task that takes you there. Unknown paths resolve to their nearest
known ancestor, and the explainer says how to reason about the rest.

Drill: a pool of questions; `drill_pick(doy)` chooses 10 of them by
a day-of-year offset — pure function of the day, so the same day
always deals the same set, and proof can re-run it.
"""

FHS = {
    "/": ("the root of the tree",
          "Everything hangs off /. One tree, many devices: other "
          "filesystems are grafted onto directories of this one by "
          "mounting. The admin task here is orientation — when lost, "
          "pwd, then walk up."),
    "/etc": ("host-specific configuration",
             "This machine's config, as editable text: /etc/passwd "
             "and /etc/shadow (accounts), /etc/fstab (mounts), "
             "/etc/ssh/ (the SSH daemon), /etc/sudoers and "
             "sudoers.d/. Task: nearly every 'configure the service' "
             "job starts here — edit, validate, reload."),
    "/usr": ("the installed system: programs, libraries, docs",
             "The bulk of the OS as the package manager laid it "
             "down. Historically 'Unix System Resources'. Task: "
             "almost none directly — you manage /usr through the "
             "package manager, not by hand."),
    "/usr/bin": ("user executables",
                 "The normal commands live here (and /bin points "
                 "here on modern distros). Task: when a command is "
                 "'missing', check it's installed and that this is "
                 "on PATH — which/command -v answers both."),
    "/usr/sbin": ("administrator executables",
                  "The root-flavoured commands: useradd, visudo, "
                  "sshd itself. Often not on a normal user's PATH, "
                  "which is why 'command not found' sometimes means "
                  "'use sudo or the full path'."),
    "/usr/local": ("locally installed software",
                   "Yours, not the distro's: things you built or "
                   "installed outside the package manager. Package "
                   "upgrades don't touch it. Task: this is where "
                   "your own scripts and builds belong (/usr/local/"
                   "bin) — and where a stranger's build hiding here "
                   "is worth a question."),
    "/var": ("variable data — the parts that grow",
             "Logs, spools, caches, databases, web content: "
             "everything that changes while the system runs. Task: "
             "when a disk fills, it is usually /var that grew; "
             "du -xhd1 /var is the first look."),
    "/var/log": ("the logs",
                 "auth.log (Debian family) or secure (RHEL family) "
                 "for logins and sudo, syslog/messages for the "
                 "general stream, plus per-service files. Task: "
                 "incident reading starts here (or in journalctl); "
                 "navi-scribe turns these into timelines. Managed "
                 "by logrotate."),
    "/home": ("users' home directories",
              "One directory per human, owned by them. Task: "
              "backups start here; permissions here are privacy — "
              "a world-readable home is everyone's filing cabinet."),
    "/root": ("root's home directory",
              "Deliberately NOT under /home: it sits on the root "
              "filesystem so it exists in rescue situations when "
              "/home isn't mounted. Task: root's own scripts and "
              "keys — and a reason to not run daily life as root "
              "just to be near them."),
    "/tmp": ("world-writable scratch (sticky bit)",
             "Temporary files for everyone: mode 1777, sticky bit "
             "on, so users can create but only delete their own. "
             "Often cleared at boot or by age. Task: never store "
             "anything precious here, and expect hardening guides "
             "to suggest mounting it noexec/nosuid/nodev."),
    "/proc": ("a window into the kernel and every process",
              "A VIRTUAL filesystem: the files aren't on any disk. "
              "/proc/cpuinfo, /proc/meminfo describe the machine; "
              "/proc/<PID>/ describes a process. Task: reading "
              "state without tools — and remembering the 'files' "
              "report size 0 while having contents."),
    "/sys": ("a window into devices and drivers",
             "/proc's hardware twin: kernel objects for devices, "
             "drivers, buses. Task: mostly reading device state; "
             "some values are writable to change kernel behaviour "
             "live (carefully). Managed alongside udev."),
    "/dev": ("device files — hardware as files",
             "/dev/sda is a disk, /dev/null eats anything written "
             "to it, /dev/urandom serves randomness. Created and "
             "managed by the kernel + udev. Task: you talk to "
             "devices through these names (dd to /dev/sdX is the "
             "loaded gun of Linux commands)."),
    "/lib": ("shared libraries (merged into /usr/lib)",
             "The .so libraries programs link against; /lib is a "
             "symlink to /usr/lib on modern merged-usr distros, as "
             "are /bin and /sbin. Task: 'error while loading "
             "shared libraries' sends you here and to ldconfig."),
    "/usr/lib": ("shared libraries",
                 "Where the linker's world lives. Task: ldd <binary> "
                 "shows which of these a program needs; a missing "
                 "line in ldd output is the whole diagnosis."),
    "/boot": ("kernel, initramfs, bootloader",
              "vmlinuz-*, initrd images, grub config. Often its "
              "own small partition. Task: old kernels accumulate "
              "here and fill it — 'no space left' during a kernel "
              "update is this directory's signature failure."),
    "/opt": ("add-on third-party packages",
             "Self-contained vendor software that doesn't spread "
             "itself across /usr: one folder per product. Task: "
             "when something was 'installed' but no package owns "
             "it, look here (and /usr/local) before concluding "
             "anything."),
    "/srv": ("data served by this machine's services",
             "Web roots and file-service data, by the standard. "
             "In practice many distros put web content in "
             "/var/www instead — know both, check which your "
             "service uses. Task: content lives here; config "
             "lives in /etc."),
    "/mnt": ("manual mount point",
             "The traditional empty directory where an admin "
             "mounts something by hand, temporarily. Task: "
             "mount /dev/... /mnt — the rescue-and-inspect move."),
    "/media": ("removable media, automounted",
               "Where the desktop automounts USB drives and cards "
               "(usually /media/<user>/<label>). Task: the "
               "difference from /mnt is intent — system-managed "
               "and temporary vs manual."),
    "/run": ("runtime state since boot",
             "A tmpfs (RAM) filesystem: PID files, sockets, locks "
             "for the current boot only; /run/user/<uid> holds "
             "your session's sockets. Task: everything here is "
             "recreated at boot — never store config in it, and "
             "check it when a daemon's socket 'isn't there'."),
}


def _parent(path):
    if path == "/":
        return "/"
    head = path.rsplit("/", 1)[0]
    return head if head else "/"


def resolve_fhs(raw):
    """(matched_path, (title, body), exact) for a user-given path.

    Walks up to the nearest known ancestor. Absolute or relative
    input both accepted; the walk always ends at '/' at worst."""
    p = (raw or "").strip()
    if not p:
        p = "/"
    if not p.startswith("/"):
        p = "/" + p
    if len(p) > 1:
        p = p.rstrip("/")
    exact = p in FHS
    cur = p
    while cur not in FHS:
        cur = _parent(cur)
    return cur, FHS[cur], exact


def render_fhs(raw):
    matched, (title, body), exact = resolve_fhs(raw)
    shown = (raw or "/").strip() or "/"
    if exact:
        head = "%s — %s" % (matched, title)
        return "%s\n%s" % (head, body)
    return ("%s — no dedicated entry; its nearest known ancestor is "
            "%s.\n%s — %s\n%s\nHow to reason about the rest: a path "
            "inherits its ancestor's PURPOSE. List it (ls -la), ask "
            "file(1) what the pieces are, and check `mount`/`df` to "
            "see whether it's a separate filesystem — purpose, "
            "owner, and mount tell you almost everything."
            % (shown, matched, matched, title, body))


def render_fhs_overview():
    out = ["the map — Filesystem Hierarchy Standard, top level:"]
    for path in ["/", "/etc", "/usr", "/usr/bin", "/usr/sbin",
                 "/usr/local", "/usr/lib", "/var", "/var/log",
                 "/home", "/root", "/tmp", "/proc", "/sys", "/dev",
                 "/lib", "/boot", "/opt", "/srv", "/mnt", "/media",
                 "/run"]:
        out.append("  %-10s %s" % (path, FHS[path][0]))
    out.append("Ask about any path: fhs /var/log — subpaths resolve "
               "to their nearest known ancestor.")
    return "\n".join(out)


DRILL = [
    ("A file shows -rwxr-sr-x. What is the 's' doing in the group "
     "position, and what is the numeric mode?",
     "It's the setgid bit on an executable: the program runs with "
     "the file's GROUP privileges. The mode is 2755 (2 is setgid; "
     "the s replaces the group's x)."),
    ("umask is 027. A program creates a file (which asks for 666) "
     "and a directory (which asks for 777). What does each get?",
     "File 640 (rw-r-----), directory 750 (rwxr-x---). The mask "
     "only subtracts; files never ask for x, which is why 666 is "
     "the file starting point."),
    ("Which file must be edited with visudo rather than a plain "
     "editor, and why does it matter?",
     "/etc/sudoers (and its sudoers.d drop-ins). Visudo "
     "syntax-checks before saving: one typo in sudoers can break "
     "sudo everywhere, and you need sudo to fix sudo."),
    ("What is the difference between `systemctl start ssh` and "
     "`systemctl enable ssh`?",
     "start runs it NOW, this boot only. enable makes it start at "
     "every boot. enable --now does both — and the difference is "
     "the #1 cause of 'it worked until the reboot'."),
    ("/tmp is drwxrwxrwt. What does the trailing t do?",
     "Sticky bit: on a directory it means only a file's owner (or "
     "root) can delete or rename it, even though the directory is "
     "world-writable. Without it, anyone could delete anyone's "
     "temp files."),
    ("Where does sshd log, and which two ways do you read it?",
     "Into the journal — journalctl -u ssh (sshd on RHEL family) — "
     "and into /var/log/auth.log on Debian-family systems "
     "(/var/log/secure on RHEL family)."),
    ("You run `usermod -G docker alex`. What just went wrong?",
     "Without -a, -G REPLACES alex's whole supplementary group "
     "list — docker in, sudo (and everything else) out. The append "
     "form is usermod -aG docker alex. Changes need a fresh login "
     "to take effect."),
    ("ps shows a process in state Z. Will kill -9 fix it?",
     "No. Z is a zombie: already dead, waiting for its parent to "
     "reap it. Signals do nothing. Fix, signal, or restart the "
     "PARENT — or wait for the parent to exit so init adopts and "
     "reaps it."),
    ("df says / is 100% full, but du adds up to far less. Name "
     "two suspects.",
     "(1) Deleted-but-still-open files: blocks stay allocated "
     "until the holding process dies. (2) Inode exhaustion: space "
     "remains but no inodes do — check df -i."),
    ("What lives in /proc, and why can't you meaningfully tar "
     "it up?",
     "A virtual filesystem exposing kernel and per-process state "
     "as files. They're generated on read, mostly report size 0, "
     "and change constantly — there's no stable content to "
     "archive."),
    ("A shared upload directory is chmod 777. Name two distinct "
     "risks.",
     "(1) Without the sticky bit, anyone can delete or replace "
     "anyone else's files (1777 fixes exactly that). (2) If the "
     "directory is web-reachable, an uploaded file may be executed "
     "by the server — pair the perms thinking with noexec and "
     "keeping uploads outside the code path."),
    ("Why does /usr/bin/passwd carry the setuid bit?",
     "So an ordinary user can update their own record in "
     "root-owned /etc/shadow: the program runs with root's "
     "privileges for that narrow job. It's also why setuid-root "
     "binaries get audited — the same bit on the wrong program "
     "is a privilege-escalation path."),
    ("ss shows a service on 0.0.0.0:3306. What does the 0.0.0.0 "
     "mean, and why do you care?",
     "0.0.0.0 means ALL IPv4 interfaces — the database is "
     "offered to the whole network. Bound to 127.0.0.1 it would "
     "be local-only. The bind address is a security decision, "
     "not a detail."),
    ("A script runs fine from your shell but fails silently in "
     "cron at 3am. First suspect?",
     "The environment: cron gives a minimal PATH and none of "
     "your shell profile, so relative commands and assumed "
     "variables vanish. Absolute paths everywhere, and redirect "
     "output to a log so 'silently' never happens again."),
    ("In stat output, what is 'Change' time — and what is it "
     "NOT?",
     "It's the inode CHANGE time: last metadata change (chmod, "
     "chown, rename, link count). It is NOT the creation time — "
     "that's Birth, a separate field that isn't always "
     "available."),
    ("On a RHEL-family box, what manages the host firewall — and "
     "what's the Ubuntu-family equivalent?",
     "firewalld, driven by firewall-cmd (permanent rules plus a "
     "--reload). On the Ubuntu/Debian family the front-end is "
     "ufw. Zones vs flat rules; same default-deny thinking."),
]


def drill_pick(doy):
    """The 10 questions for a day-of-year (1..366): deterministic.

    Offsets the pool by the day and takes the next 10 (wrapping),
    so consecutive days overlap but differ, and the same day
    always deals the same set."""
    n = len(DRILL)
    offset = (int(doy) - 1) % n
    return [DRILL[(offset + i) % n] for i in range(10)]


def render_drill(doy):
    picks = drill_pick(doy)
    out = ["linuxkit drill — day %d set: 10 questions. Answer out "
           "loud before you scroll; the answers are folded at the "
           "end." % doy, ""]
    for i, (q, _a) in enumerate(picks, 1):
        out.append("Q%d. %s" % (i, q))
    out.append("")
    out.append("~ ~ ~ answers below — no peeking until you've "
               "committed ~ ~ ~")
    out.append("")
    for i, (_q, a) in enumerate(picks, 1):
        out.append("A%d. %s" % (i, a))
    return "\n".join(out)
