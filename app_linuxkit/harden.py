"""Hardening checklists, ordered, each step carrying its why.

Text the student reviews and applies himself on his own machines —
this module runs nothing. Posture throughout: gray hat leaning
white; the honest answers (e.g. the SSH port question) are given
as honest answers, not folklore.
"""

TOPICS = {}


def _t(name, title, items):
    TOPICS[name] = {"name": name, "title": title, "items": items}


_t("ssh", "SSH — the front door gets the most locks", [
    ("Work with keys, and put a passphrase on the key.",
     "A password can be guessed online, a few tries at a time, "
     "forever. A key cannot — the math isn't close. The passphrase "
     "protects the key file itself if it is ever copied."),
    ("Test key login in a SECOND session, then set "
     "PasswordAuthentication no in /etc/ssh/sshd_config.",
     "Removes the password-guessing surface entirely. The second "
     "session is what stands between you and the classic "
     "self-lockout."),
    ("Set PermitRootLogin no (or prohibit-password at minimum).",
     "'root' is the one username every scanner on Earth tries "
     "first. Make them guess a username AND defeat key auth."),
    ("Name who may log in: AllowUsers or AllowGroups in sshd_config.",
     "Service accounts and stale accounts should not be SSH doors "
     "at all."),
    ("On the port question, the honest answer: moving SSH off 22 "
     "buys quiet logs, not security.",
     "Drive-by scanners stop knocking, so auth.log gets readable "
     "again. But a real scanner finds services on any port in "
     "seconds — never count the move as a defense, and don't let it "
     "substitute for keys."),
    ("If password auth must stay anywhere, rate-limit the door: "
     "fail2ban, or `ufw limit ssh`.",
     "Slows online guessing from a flood to a drip."),
    ("Validate before you restart: sshd -t, then systemctl reload "
     "ssh (Debian family) or sshd (RHEL family).",
     "A config typo plus a restart is the other classic lockout. "
     "Reload applies config without dropping your live sessions."),
])

_t("users", "Users & sudo — every account is a door, sudo is the master key", [
    ("One account per human. No shared logins, ever.",
     "Logs and sudo trails must be able to name a person. A shared "
     "account is an alibi for everyone who used it."),
    ("Audit who holds sudo: the sudo/wheel group, /etc/sudoers and "
     "every file in /etc/sudoers.d/. Run sudo -l as each user.",
     "Sudo membership IS root, with extra steps. It should be a "
     "short, reviewed, deliberate list."),
    ("Hunt dormant accounts: passwd -S for status, lastlog for "
     "last-login, and ask who each account belongs to.",
     "An unused account with a two-year-old password is an "
     "unmonitored door. Nobody watches a door nobody uses."),
    ("Retire accounts properly: usermod -L to lock, shell to "
     "/usr/sbin/nologin, or usermod --expiredate 1 to expire.",
     "Each step closes a different path in; 'locked password' "
     "alone still lets SSH keys through (see cmd passwd)."),
    ("Service accounts get nologin shells and no passwords.",
     "They run daemons, not people. A service account that can "
     "log in interactively is standing risk with no benefit."),
    ("Check for extra root: grep ':0:' /etc/passwd must return "
     "exactly one line.",
     "A second UID-0 account is a root account that doesn't say "
     "'root' — the oldest hiding place there is."),
    ("Passwords: length beats complexity theater; long "
     "passphrases, a manager, MFA where the service offers it.",
     "Modern NIST guidance dropped forced rotation-and-symbol "
     "rituals because they produced Post-it passwords. Length is "
     "what guessing attacks actually pay for."),
])

_t("services", "Services — every listening socket is a promise you made", [
    ("Enumerate the surface: sudo ss -tulpn, and journal the "
     "answer somewhere you'll re-check.",
     "Every listening line is a program strangers can talk to. "
     "You can't defend a list you haven't written down."),
    ("For each listener, answer: who needs this, and from where?",
     "If the honest answer is 'nobody, anymore' — systemctl "
     "disable --now it. Unused services are unpatched services."),
    ("Bind local-only things to 127.0.0.1 (databases above all).",
     "A socket bound to loopback cannot be reached from the "
     "network at all. That is stronger than any firewall rule, "
     "because there is nothing to misconfigure later."),
    ("Daemons run as their own unprivileged users, never as root "
     "by default.",
     "When (not if) a service is compromised, its user's "
     "permissions are the blast radius."),
    ("Review what starts at boot: systemctl list-unit-files "
     "--state=enabled.",
     "The reboot is when surprises return. Enabled is a promise "
     "made to every future boot, including the one after an "
     "incident."),
    ("See the surface from outside with your own scanner.",
     "That's navi-recon's job — scan your lab boxes the way a "
     "stranger would, and compare against your ss list. And read "
     "what those services write: navi-scribe's job."),
])

_t("updates", "Updates — the unglamorous control that stops most breaches", [
    ("Patch on a rhythm: apt update && apt upgrade, or dnf "
     "upgrade, weekly at worst.",
     "Most real-world compromises use vulnerabilities that "
     "already had fixes. The gap between 'fix published' and "
     "'fix installed' is the attacker's whole business model."),
    ("Turn on automatic SECURITY updates on servers: "
     "unattended-upgrades (Debian family) or dnf-automatic (RHEL).",
     "Humans forget rhythms; daemons don't. Keep feature upgrades "
     "manual, security fixes automatic."),
    ("Know when a reboot is owed: /var/run/reboot-required "
     "(Debian family) or needs-restarting (RHEL family).",
     "A new kernel that never boots is not an installed fix. "
     "Libraries in use by running processes have the same issue."),
    ("Snapshot or back up before big upgrades.",
     "The undo button turns a scary upgrade into a routine one — "
     "which means upgrades actually happen."),
    ("Audit your software sources once in a while: every repo and "
     "PPA in the list.",
     "Each one is trusted code installed as root. Yesterday's "
     "helpful PPA is today's abandoned (or sold) supply chain."),
])

_t("logging", "Logging — the evidence you'll wish you had", [
    ("Know your two log worlds: the journal (journalctl) and "
     "/var/log — auth.log on Debian family, secure on RHEL family.",
     "Different shapes, different tools. An incident read starts "
     "with knowing which world the record lives in."),
    ("Watch authentication first: failed logins, successful "
     "logins after failures, sudo use, new accounts.",
     "That's the break-in storyline, and navi-scribe parses and "
     "flags exactly these shapes — paste it the log and it "
     "builds the timeline."),
    ("Keep the clocks honest: systemd-timesyncd / NTP sync on "
     "every box.",
     "Correlating two machines' logs with a four-minute skew is "
     "archaeology, not analysis. Time sync is a logging control."),
    ("Mind the space: journalctl --disk-usage, logrotate for "
     "/var/log, and include /var in your df checks.",
     "A full /var is a classic self-inflicted outage — and a "
     "full disk also means logs STOP, usually during the "
     "incident that filled it."),
    ("Understand the limit: local logs are editable by whoever "
     "owns the box.",
     "Root can rewrite history. The grown-up answer is shipping "
     "logs off the machine (remote syslog/journal upload) — "
     "know it as the next level, even in a home lab."),
])

_t("firewall", "Host firewall — default deny, then deliberate holes", [
    ("Set the posture first: sudo ufw default deny incoming; "
     "sudo ufw default allow outgoing.",
     "Everything else is an exception to this sentence. Outgoing "
     "stays open because a workstation that can't ask questions "
     "is unusable; servers can tighten later."),
    ("Allow SSH BEFORE enabling, if SSH is how you're connected.",
     "sudo ufw allow 22/tcp (or your port), THEN sudo ufw "
     "enable. Reversed, this is the lockout story everyone "
     "tells once."),
    ("Open services one rule at a time, scoped where you can: "
     "ufw allow from 192.168.1.0/24 to any port 445 proto tcp.",
     "'The LAN may reach file sharing' is a policy. 'Anyone may' "
     "is an accident you haven't noticed yet."),
    ("Verify from the outside: ufw status verbose here, and a "
     "scan from another machine (navi-recon).",
     "The firewall's opinion and the network's reality should "
     "agree. When they don't, the network is right."),
    ("Remember the layers: host firewall, network firewall, and "
     "plain not-listening are three different controls.",
     "A service bound to 127.0.0.1 needs no rule. A disabled "
     "service needs no rule. The quietest rule is the socket "
     "that never opened."),
    ("On RHEL-family systems the same thinking wears a different "
     "uniform: firewalld (firewall-cmd --permanent, then "
     "--reload).",
     "Zones instead of a flat list, same law: default deny, "
     "named exceptions, verify from outside."),
])


def render_topic(name):
    topic = TOPICS.get((name or "").strip().lower())
    if topic is None:
        return None
    out = ["harden %s — %s" % (topic["name"], topic["title"]), ""]
    for i, (step, why) in enumerate(topic["items"], 1):
        out.append("%d. %s" % (i, step))
        out.append("   Why: %s" % why)
    return "\n".join(out)


def topic_names():
    return list(TOPICS.keys())
