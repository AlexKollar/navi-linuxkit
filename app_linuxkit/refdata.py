"""The command reference: what each admin command does, the flags
that actually matter, one realistic example, and the trap ('careful:').

Data only — rendering lives in core.py. Entries were kept to claims
the author can stand behind against the man pages; where distros
diverge the entry says so.
"""


def _e(name, title, usage, flags, example, careful, aliases=()):
    return {"name": name, "title": title, "usage": usage,
            "flags": flags, "example": example, "careful": careful,
            "aliases": list(aliases)}


COMMANDS = {}


def _add(entry):
    COMMANDS[entry["name"]] = entry
    for a in entry["aliases"]:
        COMMANDS[a] = entry


_add(_e(
    "ls", "list directory contents",
    "ls [flags] [path]",
    [("-l", "long format: permissions, owner, size, modified time"),
     ("-a", "include dotfiles (the hidden half of every home dir)"),
     ("-h", "human-readable sizes — pair with -l"),
     ("-t", "sort by modification time, newest first (-lt finds the "
            "freshest log)"),
     ("-R", "recurse into subdirectories")],
    "ls -lah /var/log",
    "Never parse ls output in a script — filenames can contain spaces "
    "and newlines, and the columns shift with size units. Use find or "
    "shell globs for anything a script depends on.",
))

_add(_e(
    "cd", "change directory (a shell builtin, not a program)",
    "cd [dir]   |   cd -   |   cd ..   |   cd ~",
    [("-", "jump back to the previous directory — the OLDPWD ping-pong"),
     ("..", "one level up; ../.. two levels"),
     ("~", "your home directory (also bare `cd`)")],
    "cd /etc/ssh && pwd",
    "Because cd is a builtin, a script's cd changes nothing for the "
    "shell that launched it. Worse: if `cd /somewhere` fails inside a "
    "script, the following commands run in the WRONG directory — "
    "guard it: cd /somewhere || exit 1.",
))

_add(_e(
    "file", "identify a file by its contents (magic bytes), not its name",
    "file [flags] <file>...",
    [("-b", "brief: the answer without the filename"),
     ("-i", "answer as a MIME type (text/plain, application/pdf...)"),
     ("-L", "follow symlinks and describe the target"),
     ("-z", "look inside compressed files too")],
    "file /usr/bin/passwd   ->   setuid ELF 64-bit LSB pie executable...",
    "Extensions lie. A 'photo.jpg' that file calls an executable is "
    "the whole lesson — in forensics and in email attachments, trust "
    "magic bytes over names every time.",
))

_add(_e(
    "stat", "full inode metadata for a file: perms, owner, all the times",
    "stat [flags] <file>",
    [("-c FORMAT", "print only what you ask: %a octal perms, %U owner, "
                   "%n name  ->  stat -c '%a %U %n' /etc/shadow"),
     ("-f", "report on the FILESYSTEM instead of the file")],
    "stat -c '%a %U %n' /etc/shadow   ->   640 root /etc/shadow",
    "Change time (ctime) is NOT creation time — it is when the inode's "
    "metadata last changed (chmod, chown, rename). Birth time exists "
    "on newer filesystems but is often blank; and atime is usually "
    "relatime-mounted, so don't build incident timelines on atime.",
))

_add(_e(
    "chmod", "change permission bits, symbolically or in octal",
    "chmod [flags] <mode> <file>...",
    [("-R", "recursive — descends the whole tree"),
     ("-v", "say what changed"),
     ("--reference=F", "copy F's permissions exactly"),
     ("u+x / g-w / a=r", "symbolic form: who (u/g/o/a), +/-/=, bits")],
    "chmod 750 ~/scripts/backup.sh",
    "chmod -R 777 is the classic self-own: every file world-writable "
    "and executable, in places you forgot existed. Also know the "
    "kernel ignores the setuid bit on shell scripts — only real "
    "binaries can carry it.",
))

_add(_e(
    "chown", "change a file's owner and/or group",
    "chown [flags] <owner>[:<group>] <file>...",
    [("-R", "recursive"),
     ("owner:group", "the colon form sets both at once"),
     ("--reference=F", "copy F's ownership")],
    "sudo chown -R www-data:www-data /var/www",
    "Needs root for anything interesting. Changing a file's owner "
    "quietly strips its setuid/setgid bits — the kernel does that on "
    "purpose, and it surprises people who 'just fixed ownership' on "
    "a privileged binary.",
))

_add(_e(
    "useradd", "create a user account (low-level; writes /etc/passwd & co)",
    "useradd [flags] <name>",
    [("-m", "create the home directory — without it, there is none"),
     ("-s", "login shell, e.g. -s /bin/bash (default comes from "
            "/etc/default/useradd and may be a bare sh)"),
     ("-G", "supplementary groups, comma-separated"),
     ("-c", "comment field (GECOS) — the human's real name")],
    'sudo useradd -m -s /bin/bash -c "Lab User" labuser',
    "On Debian/Ubuntu, useradd is the plumbing and adduser is the "
    "friendly interactive wrapper — know which one your course means. "
    "A fresh account has no password and is locked until passwd runs; "
    "that's a feature.",
))

_add(_e(
    "usermod", "modify an existing account",
    "usermod [flags] <name>",
    [("-aG", "APPEND to supplementary groups — the -a is the point"),
     ("-G", "REPLACE supplementary groups (see careful:)"),
     ("-L / -U", "lock / unlock the password"),
     ("-s", "change login shell (-s /usr/sbin/nologin disables login)"),
     ("-l", "rename the login; -d -m changes and moves home")],
    "sudo usermod -aG sudo alex",
    "usermod -G group user WITHOUT -a replaces the entire group list "
    "— it's the standard way admins remove themselves from sudo and "
    "lock the box. Group changes also need a fresh login to take "
    "effect; the current session keeps its old groups.",
))

_add(_e(
    "userdel", "delete a user account",
    "userdel [flags] <name>",
    [("-r", "also remove the home directory and mail spool"),
     ("-f", "force — even if the user is logged in")],
    "sudo userdel -r oldstudent",
    "-r deletes the home directory for good. Files the user owned "
    "ELSEWHERE stay behind, owned by a bare number — orphaned files. "
    "Before deleting: find / -uid <UID> -print 2>/dev/null to see "
    "what you'd be orphaning.",
))

_add(_e(
    "groupadd", "create a group",
    "groupadd [flags] <name>",
    [("-g", "choose the GID explicitly"),
     ("-r", "system group (low GID range)")],
    "sudo groupadd -g 1050 analysts",
    "The kernel checks the GID NUMBER, not the name. Two machines "
    "sharing files (NFS, a mounted drive) with the same group NAME "
    "but different numbers have different groups — pick GIDs "
    "deliberately on shared systems.",
))

_add(_e(
    "passwd", "set passwords and password aging/status",
    "passwd [flags] [user]",
    [("-S", "status: who, locked or not, aging values"),
     ("-l / -u", "lock / unlock the account's password"),
     ("-e", "expire now — forces a change at next login"),
     ("-x / -n", "max / min days between changes (aging policy)")],
    "sudo passwd -e newhire",
    "Locking (-l) blocks PASSWORD logins only — an SSH key still "
    "works, so locking is not disabling (usermod --expiredate 1 is). "
    "And passwd -d deletes the password entirely: a passwordless "
    "account, not a locked one.",
))

_add(_e(
    "systemctl", "control systemd: services, boot behaviour, unit state",
    "systemctl <verb> [unit]",
    [("enable --now", "start at every boot AND start right now — "
                      "the two-in-one you'll type most"),
     ("status", "is it running, since when, last log lines"),
     ("mask", "stronger than disable: the unit cannot be started at "
              "all, even as a dependency"),
     ("daemon-reload", "re-read unit files after you edit one")],
    "sudo systemctl enable --now ssh",
    "Start is not enable: a started-but-not-enabled service dies at "
    "the next reboot ('it worked until it didn't'). And after editing "
    "a unit file, forgetting daemon-reload means the OLD config "
    "keeps running.",
))

_add(_e(
    "journalctl", "read the systemd journal (the binary system log)",
    "journalctl [flags]",
    [("-u UNIT", "one service's entries only"),
     ("-b", "this boot; -b -1 is the previous one — the boot that "
            "crashed"),
     ("-p err", "priority err and worse (emerg..err scale)"),
     ("-f", "follow — tail -f for the journal"),
     ("--since", "'--since \"1 hour ago\"' or a date")],
    "journalctl -u ssh -p err --since today",
    "If /var/log/journal doesn't exist, the journal may live only in "
    "RAM and vanish at reboot — absence of a line is not proof the "
    "event didn't happen. Journal format also differs from the flat "
    "syslogs navi-scribe parses; know which one you're reading.",
))

_add(_e(
    "ss", "socket statistics — what is listening and connected (netstat's heir)",
    "ss [flags]",
    [("-t / -u", "TCP / UDP sockets"),
     ("-l", "listening sockets only — your attack surface, one screen"),
     ("-n", "numeric: no DNS or service-name lookups (faster, exact)"),
     ("-p", "which process owns each socket (needs sudo for other "
            "users' processes)")],
    "sudo ss -tulpn",
    "ss shows SOCKETS, not firewall verdicts. A port listening on "
    "127.0.0.1 is local-only; the same port on 0.0.0.0 is offered to "
    "the whole network — the address column is the security column.",
))

_add(_e(
    "ip", "interfaces, addresses, routes — the iproute2 toolkit",
    "ip <object> <action>   (a=addr, link, route, neigh)",
    [("-br a", "brief address list: interface + IPs, one line each"),
     ("route", "routing table; `ip route show default` = your gateway"),
     ("link set", "bring interfaces up/down, change MAC (lab use)")],
    "ip -br a && ip route show default",
    "Changes made with ip are RUNTIME-ONLY: they evaporate at "
    "reboot. Persistence lives in netplan/NetworkManager config and "
    "differs by distro — the CIS lab trap is 'fixing' an address "
    "that returns on Monday.",
))

_add(_e(
    "ps", "process snapshot — who is running what, owned by whom",
    "ps [flags]",
    [("aux", "BSD style: all users, user-oriented columns (USER, "
             "%CPU, %MEM, STAT, COMMAND)"),
     ("-ef", "SysV style: every process, full format (PPID column)"),
     ("--forest", "indent the parent/child tree (or ps auxf)"),
     ("-o", "choose columns: ps -eo pid,ppid,user,stat,cmd")],
    "ps aux | grep -i sshd   —   better: pgrep -a sshd",
    "State Z means zombie: already dead, waiting for its parent to "
    "notice. You cannot kill a zombie (even -9) — fix or restart the "
    "PARENT. Also: grep in a ps pipeline matches itself; pgrep "
    "exists precisely to avoid that noise.",
))

_add(_e(
    "top", "live process monitor",
    "top [flags]   (keys inside: P cpu, M memory, k kill, 1 per-core, q quit)",
    [("-b -n 1", "batch mode: one snapshot to a pipe or file — the "
                 "scripting form"),
     ("-u user", "only one user's processes"),
     ("-p PID", "watch specific processes")],
    "top -b -n 1 | head -20",
    "%CPU in top is per-core: a busy multithreaded process honestly "
    "shows 300% on a 4-core box. And load average is not a CPU "
    "percentage — it's the queue of runnable + waiting processes "
    "over 1/5/15 minutes.",
))

_add(_e(
    "kill", "send a SIGNAL to a process (termination is just one signal)",
    "kill [-SIGNAL] <PID>...",
    [("-l", "list the signals: TERM 15, KILL 9, HUP 1, STOP 19..."),
     ("-15 TERM", "the default: 'shut down cleanly, please'"),
     ("-9 KILL", "uncatchable, immediate, no cleanup — last resort"),
     ("-HUP", "many daemons read HUP as 'reload your config'")],
    "kill 1234; sleep 2; kill -9 1234   # ask first, force second",
    "A process in D state (uninterruptible sleep — stuck I/O) "
    "ignores even -9 until the kernel operation returns. And -9 "
    "first is malpractice: no flushing, no cleanup, corrupted state "
    "files. TERM, wait, then KILL.",
))

_add(_e(
    "df", "free space per mounted filesystem",
    "df [flags] [path]",
    [("-h", "human-readable sizes"),
     ("-T", "show filesystem types"),
     ("-i", "inode usage — the OTHER way a disk fills")],
    "df -hT / && df -i /",
    "'Filesystem full' with gigabytes free usually means inode "
    "exhaustion (millions of tiny files) — check df -i. And when df "
    "and du disagree about a filesystem, deleted-but-still-open "
    "files are holding the space until their process dies.",
))

_add(_e(
    "du", "disk usage summed by directory",
    "du [flags] [dir]",
    [("-h", "human-readable"),
     ("-s", "summary only: one number for the whole tree"),
     ("-d 1 / --max-depth", "report per top-level child — the "
                            "'who ate /var' view: du -xhd1 /var | sort -h"),
     ("-x", "stay on one filesystem — don't cross mounts")],
    "sudo du -xhd1 /var | sort -h",
    "du counts allocated blocks, so sparse files make it disagree "
    "with ls -l sizes (--apparent-size flips the view). Without -x "
    "it will cheerfully wander into other mounted filesystems and "
    "blame the wrong disk.",
))

_add(_e(
    "mount", "attach filesystems; bare `mount` lists what's attached",
    "mount [flags] <device> <dir>   |   mount -a",
    [("-o", "options: ro, noexec, nosuid, nodev, remount"),
     ("-a", "mount everything in /etc/fstab — run this after "
            "editing fstab, before trusting a reboot"),
     ("--bind", "mount a directory onto another directory")],
    "sudo mount -o remount,noexec,nodev /tmp",
    "A typo in /etc/fstab can drop the machine into emergency mode "
    "at boot — always `mount -a` after editing, and keep a rescue "
    "path. The /tmp options above are real hardening, but noexec "
    "breaks installers that execute from /tmp.",
))

_add(_e(
    "tar", "archive files into one file (optionally compressed)",
    "tar <mode> [flags] <archive> [files]",
    [("-c / -x / -t", "create / extract / LIST — list before you "
                      "extract, always"),
     ("-f", "the archive file — without it tar talks to a tape "
            "device like it's 1979"),
     ("-z / -J", "gzip / xz compression (-a picks by extension)"),
     ("-C dir", "change into dir before extracting")],
    "tar -tzf backup.tar.gz | head -30",
    "Extracting as root preserves the archive's owners, permissions "
    "and setuid bits by default — tar trusts the archive. List "
    "first, extract as a normal user, and never pipe a stranger's "
    "tarball into sudo tar -x.",
))

_add(_e(
    "grep", "search text with patterns",
    "grep [flags] <pattern> <files>",
    [("-i", "case-insensitive"),
     ("-r", "recurse through directories"),
     ("-n", "show line numbers; -c shows counts only"),
     ("-E", "extended regex; -F means literal fixed string instead"),
     ("--color", "highlight matches (usually aliased on)")],
    'grep -in "failed password" /var/log/auth.log',
    "Patterns are regexes: . matches ANY character, and a pattern "
    "starting with - is eaten as a flag (use grep -e '-x' or --). "
    "For real log analysis at scale, that's navi-scribe's job — "
    "grep is the pocket knife, scribe is the workbench.",
))

_add(_e(
    "find", "find files by metadata: name, type, age, size, permissions",
    "find <where> <tests> [actions]",
    [("-name / -iname", "match the name (case-sensitive / not)"),
     ("-perm -4000", "permission search — this form means 'all "
                     "these bits set': the setuid audit"),
     ("-mtime / -mmin", "modified more/less than n days/minutes ago "
                        "(-mtime -1 = last 24h)"),
     ("-exec cmd {} +", "run cmd on the results (+ batches them)"),
     ("-maxdepth", "limit descent depth")],
    "find / -xdev -perm -4000 -type f 2>/dev/null",
    "find with -delete or -exec rm is irreversible and immediate. "
    "Always run the same find with -print first and read the list "
    "before you let it act. -delete also forces depth-first, which "
    "deletes the directories themselves once empty.",
))

_add(_e(
    "ssh", "secure shell client: encrypted login, tunnels, jump hosts",
    "ssh [flags] [user@]<host>",
    [("-p", "port (lowercase p)"),
     ("-i", "identity (key) file for this connection"),
     ("-J", "jump host: ssh -J bastion user@inside"),
     ("-L / -D", "local port forward / dynamic SOCKS proxy tunnel"),
     ("-v", "verbose: watch the handshake and auth attempts (-vvv "
            "for the full story)")],
    "ssh -i ~/.ssh/lab_key -p 2222 alex@192.168.1.242",
    "'REMOTE HOST IDENTIFICATION HAS CHANGED' is a stop sign, not "
    "a speed bump — verify the new key out-of-band before deleting "
    "the known_hosts line. And prefer -J over agent forwarding (-A): "
    "-A hands your key agent to anyone with root on the far box.",
))

_add(_e(
    "scp", "copy files over SSH",
    "scp [flags] <source> <dest>   (either side may be user@host:path)",
    [("-P", "port — CAPITAL P here (ssh uses -p; scp's -p is "
            "'preserve times')"),
     ("-r", "recursive — directories"),
     ("-i", "identity file"),
     ("-p", "preserve modification times and permissions")],
    "scp -P 2222 report.txt alex@192.168.1.242:~/",
    "The -P/-p split has bitten every admin alive. Also: scp "
    "cannot resume a partial transfer — for big or flaky moves use "
    "rsync -avz -e ssh, which can. Modern scp (OpenSSH 9+) speaks "
    "SFTP under the hood by default.",
))

_add(_e(
    "ufw", "Uncomplicated Firewall — the Debian/Ubuntu-family host firewall",
    "ufw <verb> [rule]",
    [("status verbose", "rules, defaults, and logging state"),
     ("default deny incoming", "the posture everything else hangs "
                               "from"),
     ("allow 22/tcp", "open a service port; 'limit ssh' rate-limits "
                      "instead"),
     ("allow from NET", "scope a rule to a source network — the "
                        "grown-up form")],
    "sudo ufw default deny incoming; sudo ufw allow 22/tcp; sudo ufw enable",
    "On a machine you reach BY SSH, allow your SSH port BEFORE "
    "`ufw enable` or you will lock yourself out mid-command — the "
    "classic rite of passage. ufw is the Debian family tool; RHEL "
    "family uses firewalld (firewall-cmd) for the same job.",
))

_add(_e(
    "apt", "package management for the Debian/Ubuntu family",
    "apt <verb> [package]",
    [("update", "refresh the package LISTS — installs nothing"),
     ("upgrade / full-upgrade", "install newer versions (full- may "
                                "remove packages to resolve deps)"),
     ("install / remove / purge", "purge also deletes the config "
                                  "files remove leaves behind"),
     ("autoremove", "clear orphaned dependencies")],
    "sudo apt update && sudo apt upgrade",
    "update and upgrade are different verbs — 'I ran apt update' "
    "patched nothing. And every repository you add is trusted code "
    "running as root at install time: random PPAs are a supply-chain "
    "decision, not a shortcut.",
))

_add(_e(
    "dnf", "package management for the RHEL/Fedora family (yum's successor)",
    "dnf <verb> [package]",
    [("install / update / remove", "the daily verbs; update == upgrade "
                                   "here"),
     ("check-update", "list what WOULD update (exit 100 means "
                      "'updates exist')"),
     ("provides", "dnf provides */ss — which package owns a file or "
                  "command"),
     ("history", "past transactions; history undo <id> rolls one "
                 "back (mostly)")],
    "sudo dnf install -y httpd && dnf provides '*/journalctl'",
    "Same trust law as apt: an enabled repo is code you'll run as "
    "root. Also know module streams can hold a package at an older "
    "major version by design — 'dnf says no update' can be a "
    "stream choice, not a broken system.",
))

_add(_e(
    "crontab", "your personal cron table: scheduled commands",
    "crontab [-e | -l | -r] [-u user]",
    [("-e", "edit your table (opens $EDITOR)"),
     ("-l", "list it — run this BEFORE -e on a new machine"),
     ("-r", "REMOVE the whole table (one key from -e, no undo)"),
     ("m h dom mon dow", "the five fields: minute hour day-of-month "
                         "month day-of-week, then the command")],
    "15 3 * * 1  /home/alex/scripts/backup.sh >> /home/alex/backup.log 2>&1",
    "Cron's environment is bare: minimal PATH, no shell profile — "
    "jobs that work interactively fail silently at 3am. Use absolute "
    "paths and redirect output to a log. And dom+dow are ORed, not "
    "ANDed: restricting both runs when EITHER matches. (Systemd "
    "timers are the modern alternative your courses will meet.)",
    aliases=("cron",),
))

_add(_e(
    "sudo", "run one command (or a shell) as another user — usually root",
    "sudo [flags] <command>",
    [("-l", "list exactly what YOU are allowed to run — read this "
            "first on any new box"),
     ("-u user", "run as someone other than root"),
     ("-i", "a full login shell as the target user"),
     ("-e / sudoedit", "edit a file with your own editor but root's "
                       "write — the safe edit")],
    "sudo -l; sudo systemctl restart ssh",
    "Sudo remembers you (~15 min by default): a walked-away terminal "
    "is a root terminal. And sudoers wildcards leak shells — sudo "
    "vim, sudo less (!sh), sudo find (-exec) are all root shells in "
    "a trench coat. Least-privilege lines name exact commands.",
))

_add(_e(
    "visudo", "edit sudoers SAFELY (the only way it should be edited)",
    "visudo [-f <file>] [-c]",
    [("-c", "check mode: validate sudoers without editing"),
     ("-f", "edit a drop-in: visudo -f /etc/sudoers.d/lab")],
    "sudo visudo -f /etc/sudoers.d/labadmins",
    "A syntax error in sudoers breaks sudo EVERYWHERE — and you "
    "need sudo to fix sudo. Visudo checks before saving and locks "
    "against two editors at once. Prefer drop-ins in "
    "/etc/sudoers.d/ (mode 0440, no dots in the filename) and keep a "
    "root shell open while you change anything.",
))

GROUPS = [
    ("files & navigation", ["ls", "cd", "file", "stat"]),
    ("permissions & ownership", ["chmod", "chown"]),
    ("users & groups", ["useradd", "usermod", "userdel", "groupadd",
                        "passwd"]),
    ("services & logs", ["systemctl", "journalctl"]),
    ("network state", ["ss", "ip"]),
    ("processes", ["ps", "top", "kill"]),
    ("disk & filesystems", ["df", "du", "mount"]),
    ("search & archives", ["grep", "find", "tar"]),
    ("remote access", ["ssh", "scp"]),
    ("firewall & packages", ["ufw", "apt", "dnf"]),
    ("scheduling & privilege", ["crontab", "sudo", "visudo"]),
]


def lookup(name):
    """Entry dict for a command name/alias, or None."""
    return COMMANDS.get((name or "").strip().lower())
