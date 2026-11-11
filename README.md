# Navi Linuxkit

A Linux administration workbench that rides inside an Apex chip:
the admin command reference with the traps left in, permission math
both ways, ordered hardening checklists, and an FHS map — built for
a Computer Networking & Cyber Security student (Montco CIS 141
*Introduction to Linux* / CIS 142 *Advanced Linux*) who already lives
on Linux and wants the depth underneath it.

**Design law: Linuxkit executes nothing.** It runs no shell command
and reads no host file. It is a reference, a calculator, and a drill
sergeant — it produces text the student reviews and runs himself.
Standard library only, fully offline.

## Commands

```
linuxkit                      overview
linuxkit cmd <name>           reference for one command
linuxkit cmd                  the whole shelf, grouped
linuxkit perm <mode>          permission math — 755, rwxr-xr-x, 4755
linuxkit perm umask <mask>    what new files/dirs get under a umask
linuxkit perm special         setuid / setgid / sticky, explained
linuxkit harden <topic>       ssh | users | services | updates |
                              logging | firewall
linuxkit fhs [path]           the filesystem map, or one place in it
linuxkit drill                today's 10-question self-check
linuxkit --test               self-test
```

### cmd — the reference with teeth

33 entries: `ls cd file stat` · `chmod chown` · `useradd usermod
userdel groupadd passwd` · `systemctl journalctl` · `ss ip` ·
`ps top kill` · `df du mount` · `grep find tar` · `ssh scp` ·
`ufw apt dnf` · `crontab` (alias `cron`) `sudo visudo`.

Each entry carries what the command does, the 2–4 flags that
actually matter, one realistic example, and a **careful:** line —
the destructive or security-relevant trap (the `usermod -G`
without `-a` wipe, enabling ufw before allowing SSH, `passwd -d`
vs `-l`, why a zombie can't be killed).

### perm — permission math, both directions

- `perm 755` / `perm 4755` → symbolic form plus a who-can-do-what
  breakdown, with file-vs-directory meaning for every bit.
- `perm rwxr-xr-x` (or the 10-character ls form `-rwxr-xr-x` /
  `drwxr-xr-x`) → the number.
- `perm umask 027` → files 640, directories 750, and why files ask
  for 666 while directories ask for 777.
- `perm special` → setuid/setgid/sticky with the classic examples:
  `/usr/bin/passwd`, the setgid shared folder, `/tmp` at 1777.

### harden — checklists, ordered, each step with its why

ssh (keys first, the honest answer on moving the port), users &
sudo, services (your listening surface; navi-recon scans it,
navi-scribe reads what it writes), updates, logging, and the host
firewall (default deny, SSH allowed *before* enable).

### fhs — the map

Ask about any path (`fhs /var/log`); subpaths resolve to their
nearest known ancestor and say so, with a short how-to-reason
about the rest.

### drill

Ten questions, rotated deterministically by day of year — the same
day always deals the same set — with the answers folded at the end
of the output. Permissions, services, users, FHS.

## Layout

```
root.py                 entry: run(args) -> app_linuxkit.core
navi-chip.json          navi-chip/1 manifest, version 1.0.0
app_linuxkit/
    core.py             dispatcher, renderers, --test
    refdata.py          the 33 command entries (data)
    perms.py            the permission math (pure)
    harden.py           the checklists (data + render)
    learn.py            FHS map + drill (data + pure picks)
```

## Relationship to the other chips

Log *analysis* belongs to **navi-scribe** — Linuxkit's logging
checklist points at it. Seeing your listening surface from outside
belongs to **navi-recon**. Encodings and hashes belong to
**navi-cryptex**. Linuxkit is the layer underneath all of them:
the system itself.

## License

MIT — see LICENSE.
