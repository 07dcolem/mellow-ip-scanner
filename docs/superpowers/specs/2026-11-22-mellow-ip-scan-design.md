# Mellow IP Scan

Design for an Omarchy 4 shell plugin. Display name is always **Mellow IP Scan**.

## Intent

A quiet, keyboard-first local network scanner that lives on the Omarchy bar. It answers "who is on this subnet?" without nmap, root, or raw sockets, and it stays inside the Omarchy visual language.

The user wants it for the same job as Angry IP Scanner: see live hosts, latency, names, and MAC vendors, then copy or export a row. It has to feel like the other Omarchy panels, and it has to pass the marketplace security review on the mechanisms below, not on README promises.

## Goals

- Discover IPv4 hosts with ping. Optional short TCP checks on a small port list, off by default.
- Show latency, MAC, vendor, and hostname for live hosts. Unresolved names stay visibly unresolved.
- Cancel a scan and show live progress.
- Bar widget with an icon and the last alive count. Left click opens the dropdown. Middle click starts or stops. Right click re-detects the subnet.
- Dropdown `KeyboardPanel`, plus Super+Alt+N opening a real window titled Mellow IP Scan. Both views share one scan.
- Keyboard operation, copy, filters that do not rescan, last-scan persistence with a timestamp, export, range presets, and Wake-on-LAN.
- Install and run in the Omarchy 4.5 CUA VM before any git push or marketplace issue.

## Non-goals

- NetBIOS or SMB enumeration, OS fingerprinting, nmap, raw sockets, Tailscale peers, IPv6, and anything that needs root.
- A global Hyprland binding installed by the plugin. The binding is documented. It is added by hand on a machine where the user asks for it.
- Downloading an OUI database, or bundling `oui.txt` in the repository.
- Auto-scanning when the plugin loads.

## Anti-goals

- A wide always-on control surface. Range, ports, presets, filters, and export stay off the primary list.
- Unbounded work inside `omarchy-shell`: no uncapped process output, no scan larger than the host cap, no `Text` that can fetch a URL from a hostname.
- README claims the code does not implement.

## Constraints

- Plugin id: `io.github.07dcolem.mellow-ip-scan`. GitHub login is `07dcolem`. Kinds: `service` and `bar-widget` only. The dropdown is a private panel owned by the widget. The pop-out window lives on the service.
- Author: Dylan Coleman. License: MIT. Version: `0.1.0`. `CHANGELOG.md` starts with that release.
- Theme: `Style.cornerRadius`, semantic `Color.*`, `Style` alpha fills, host motion. No private palette. English `i18n/en.json` only; the brand name stays literal.
- Unprivileged commands only: `/usr/bin/ping`, and when present `/usr/bin/nc` or `/usr/bin/openbsd-nc`, `/usr/bin/getent`, `/usr/bin/avahi-resolve-address` or `/usr/bin/avahi-resolve`, `/usr/bin/wl-copy`, `/usr/bin/ip`. Python is `/usr/bin/python3 -I -S`.
- No `sudo`, `pkexec`, `setcap`, package install, or self-update.
- Security guide: `/home/dylan/.agents/skills/omarchy-plugin-security/SKILL.md`. Every mechanism in "Security mechanisms" is part of this design. A comment or a README sentence is not a control.
- Do not commit, push, or open a marketplace issue until the user has seen the plugin running in the CUA VM and said to publish.

## Approaches

1. **Many `Process` objects inside QML, one per ping.** The shell would collect child output and would have to supervise every descendant. Rejected. That is the failure mode the security review blocks, and it keeps the scan inside the shared shell process.

2. **One Python supervisor, chosen.** The service starts a single helper. The helper validates the request, runs a bounded pool, kills its own process group on cancel, and emits small lines. Durable state goes through a descriptor-checked writer. The shell only holds a capped model.

3. **A systemd user service.** Rejected. It is another install, it outlives the shell for no benefit, and removal would have to stop a unit the plugin directory no longer owns.

## Decisions locked with the user

- Pop-out: bar click opens the `KeyboardPanel`. Inside it, `v` or Open full (v) opens a `FloatingWindow` titled Mellow IP Scan. The window has no global key. Closing either surface leaves the scan running.
- Hotkey: the dropdown offers Super+Alt+N for the dropdown itself, only when that chord is free and the offer has not been dismissed. Nothing is written until `b` or Set Super+Alt+N (b). That writes one marked block to `bindings.lua`, reloads Hyprland, and restores the previous bytes if the reload reports a new config error. On the host list, `x` dismisses the offer, and the x beside it does the same. Removal does not delete the block.
- Vendor names: read `/usr/share/hwdata/oui.txt` only. No download, no bundled copy. A missing or rejected file leaves the vendor unknown.
- Default ports, used only after the user turns checks on: 22, 80, 443, 445, 3389, 9100.
- Rows: IP stays first. Name, latency, MAC, vendor, ports, and name source follow the Options order, and a column appears only when the row is wide enough. Fields that do not fit stay on the focused row. The list scrolls vertically only. Dead hosts are hidden until the user shows them.
- Export: the filtered view, CSV and plain text, under `~/Downloads`, names `mellow-ip-scan-YYYYMMDD-HHMMSS.csv` and `.txt`, mode 0600.
- Presets, the port list, column order, and filter defaults live in the widget's `shell.json` entry, written only when the user saves or changes a setting. The last scan lives in `~/.local/state/mellow-ip-scan/last-scan.json`.
- Keys: `j`/`k` and up/down move, Enter and Space activate, `s` starts or stops, `r` re-detects the subnet, `f` opens filters, `o` opens range, ports, columns, and presets, `c`/`m`/`n` copy IP, MAC, and hostname of the host you left, `e` exports, `w` sends Wake-on-LAN for that host, `Esc` steps back to that host and then closes. Enter on the host list copies its IP. In the dropdown, `v` opens the full window. While the hotkey offer is showing, `b` sets it and `x` on the host list dismisses it. On a column, Enter raises it and `x` lowers it. On a preset, Enter applies its range and `x` removes it. Hostname is `n` because the panel already uses `h` and `l`.

## Calls made in this design

- Maximum 1024 addresses per scan. A larger CIDR or range is refused before any ping. A `/24` fits. A `/22` fits. A `/21` does not.
- Pool size defaults to 32 and is clamped to 1–64 no matter what settings say. At most 8 name lookups at once. At most 8 ports, each an integer from 1 to 65535.
- Ping timeout 1 second, TCP timeout 1 second, name lookup 1 second. The whole scan has a deadline of 180 seconds. Cancel and destruction kill the helper's process group: TERM, 2 seconds, KILL.
- Wake-on-LAN is one UDP magic packet to the broadcast address of the validated scan range, destination port 9. The MAC must be six hex bytes. No second port, no directed broadcast supplied as free text.
- IPC methods on the plugin id are parameterless: `start`, `stop`, `status`, `toggleWindow`. `start` uses the already saved range. A range never arrives as an IPC argument.
- `status` returns only `{ scanning, done, total, alive, error }` with `error` capped at 160 characters. The host list is not an IPC payload.
- Primary page is the list. `f` and `o` replace that page; they are not extra columns. Export is a key, not a page. The status line after export is a string the plugin built (the timestamped file name), not a path taken from scan data.
- Hostname source is `dns`, `mdns`, or empty. Empty renders as an em dash and is what "unresolved" means.
- Filters: hide dead (default on), maximum latency in milliseconds (0 means off), open ports only, and a text query of at most 64 characters matched against IP, hostname, MAC, and vendor. Applying a filter does not start a scan.
- Preset names match `[A-Za-z0-9 ._-]{1,32}` and there are at most 8. The saved value is a range that already passed validation.
- Demo data and the README use the documentation prefix `192.0.2.0/24` and locally administered MACs. No real MAC, serial, or account id.

## Parts

### Service

`Service.qml` is the `service` entry, `keepLoaded: true`. It resolves nothing from another plugin. On load it asks the helper to read `last-scan.json` and, if the document matches the schema, shows it. Load does not scan, write, or edit `shell.json`.

The service owns the host model, the progress counters, the generation number, and the `FloatingWindow`. The bar widget resolves this singleton and falls back to an inert "scanner unavailable" state. A replacement bar that cannot see the service still renders the button and does not start its own pings.

`toggleWindow` shows the floating window, or hides it when it is already visible. Repeated calls do not create a second window.

### Bar widget and dropdown

`BarWidget.qml` uses `BarWidget` and `WidgetButton`. `moduleName` is the plugin id. `defaultSection` is `right`. `allowMultiple` is false. The button shows a small scanner mark drawn in QML (no `Image.source`) and the alive count. Tooltip text is a fixed sentence plus the count, passed through `plain()` so `<`, `>`, `&`, and C0/C1 controls are gone, and capped at 120 characters.

Left click toggles the private `KeyboardPanel`. Middle click calls `start` or `stop`. Right click re-detects the subnet, validates it, and saves it with `updateEntryInline` because that click is the explicit action.

The panel exposes `opened`, `open()`, and `close()`. Escape, outside click, and `close()` drop keyboard focus. The panel and the floating window both instantiate the same scan view against the service.

### Scan view

Pages are `list`, `filters`, and `options`. `PanelKeyCatcher` handles the keys above and sets `blocked` while a line editor has focus. `PanelHero` title is the literal `Mellow IP Scan`. Section labels are fixed catalog strings. Host rows are `Text` with `textFormat: Text.PlainText`.

There is no `TextField`, `TextArea`, `TextInput`, or `TextEdit`. Range, port list, filter query, latency threshold, and preset name use a plugin-local `PlainLine`. The installed QML-patterns skill has no `references/plain-line.md`, so `PlainLine.qml` is written to this contract: one `Text` with `textFormat: Text.PlainText`, printable characters, Backspace, Delete, Left, Right, Home, End, Enter, and Escape, no clipboard read or write, created only while that field is editing, and a length cap (range 64, ports 64, query 64, latency 6, preset name 32).

Every string that reaches `WidgetButton`, `tooltipText`, `PanelHero`, or `PanelSectionHeader` goes through `plain()` first. Values the plugin typed as literals still use `Text.PlainText`.

### Helper

`bin/scan.py` is the only process the service launches for scanning, lookup, export, copy, Wake-on-LAN, subnet detection, and state. QML invokes it as:

```text
["/usr/bin/python3", "-I", "-S", "<plugin>/bin/scan.py", "<verb>"]
```

`clearEnvironment: true`. The environment is only `PATH=/usr/bin`, `LC_ALL=C`, and `HOME` taken from the passwd entry for the euid, not from the inherited environment. No scan data is placed in argv or the environment. The request, when a verb needs one, is a JSON document on stdin, at most 8192 bytes.

Verbs are a closed set: `detect`, `scan`, `wol`, `read-state`, `write-state`, `export`, `copy`. Unknown verbs exit 2.

`scan` stdin is `{ "range": "...", "ports": [22], "portChecks": false }`. The helper re-validates. It expands at most 1024 IPv4 addresses. It refuses hostnames, IPv6, leading dashes, and any address that is not an IPv4 unicast host. Link-local and multicast are refused. Private, CGNAT, and public unicast are allowed, because the user asked for custom ranges, but the 1024 cap still holds.

Children are `/usr/bin/ping`, `/usr/bin/nc` or `/usr/bin/openbsd-nc`, `/usr/bin/getent`, and the avahi binary when it exists. Each runs with `start_new_session`, an absolute deadline, and a byte cap read from the pipe before line assembly (`cap + 1`, then reject). Ping is numeric (`-n`), one probe, one second. The helper checks `ping -V` or the accepted flags once on the Omarchy 4.5 VM and records the exact argv in a comment next to the call. TCP checks run only for hosts that answered ping, and only when `portChecks` is true. Name lookups run only for live hosts: `getent hosts <ip>` first, then avahi when the binary exists. Output that is not a single hostname of at most 253 characters, or that contains controls, becomes unresolved.

Progress and host records are NDJSON on stdout. Each line is at most 1024 bytes. The service counts bytes and lines, drops a late generation, and SIGTERMs the helper when the cap trips. There is no `StdioCollector`. The QML parser splits on newlines and also enforces the same line cap; it does not wait for an unbounded buffer.

`/proc/net/arp` is read from a constant path with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`, then at most 256 KiB. It is a proc file, so the regular-file owner check used for our state file does not apply. `/usr/bin/ip -4 neigh show` is a bounded supplement when the ARP row is missing. MAC addresses are accepted only as six hex bytes.

Vendor lookup opens the constant path `/usr/share/hwdata/oui.txt` with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, requires a regular file, and streams it. It does not load the file into QML. The vendor string is capped at 64 characters and stripped of controls and `<`, `>`, `&`. A missing file, a symlink, or a file larger than 16 MiB yields an empty vendor. The in-memory cache is an LRU of 512 entries.

Wake-on-LAN builds the magic packet in Python and sends one UDP datagram. It does not invoke a shell.

### State and settings

State I/O follows the descriptor helper in the security skill appendix, with the leaf directory `.local/state/mellow-ip-scan` walked from the passwd home using held directory descriptors. The leaf is 0700. `last-scan.json` is 0600 from creation, written to an exclusive temporary on the same dirfd, fsynced, then renamed over the destination. `ENOENT` means "no last scan". Any other rejection is an error and does not delete the file. The document is rejected as a whole when it exceeds 512 KiB, 1024 hosts, the string caps, or the schema. Non-finite numbers are rejected.

Settings keys, clamped again in code: `range` (string, default empty until detect), `portChecks` (bool, default false), `ports` (string, default `22, 80, 443, 445, 3389, 9100`), `hideDead` (bool, default true), `maxLatencyMs` (int 0–10000, default 0), `openPortsOnly` (bool, default false), `presets` (array, max 8). Writes go through `updateEntryInline` on explicit save, re-detect, or port-toggle actions. Nothing writes settings from `Component.onCompleted`.

### Export and copy

`export` writes only the filtered hosts the view is showing. The helper renders CSV and text. CSV fields are quoted, and a field that starts with `=`, `+`, `-`, `@`, tab, or CR is prefixed with a quote so a spreadsheet does not treat it as a formula. The destination directory is `Downloads` under the passwd home, opened with the same directory walk. Downloads itself is not chmodded. Each output file is created `O_CREAT|O_EXCL|O_NOFOLLOW` at mode 0600 under a random temporary name in that directory, then renamed to the timestamped name. The timestamp comes from the clock, not from host data. Total export bytes are capped at 512 KiB.

`copy` writes the cell text to `/usr/bin/wl-copy` on stdin, with `--` before any argument the tool still needs. The text is capped at 512 bytes. If `wl-copy` is absent, the status line says copy is unavailable.

### Removal

README states:

`omarchy plugin remove io.github.07dcolem.mellow-ip-scan`

That removes the plugin directory and the bar entry the shell tracks. It does not delete `~/.local/state/mellow-ip-scan/` or `~/Downloads/mellow-ip-scan-*.csv` and `.txt`. Those stay until the user deletes those exact paths. The README lists them. There is no `rm -rf` uninstaller. The Super+Alt+N line, if the user added it, stays in their bindings until they remove that line.

No daemon is left running: the helper is a child of the service and is killed on destruction and on plugin disable.

## Security mechanisms

These are the review rules as they apply here. Implement each one. Do not weaken one because another exists.

- No `Text` without `textFormat: Text.PlainText`. No Qt text input. No clipboard access except the explicit `copy` and export-copy verbs, which pipe to `wl-copy`.
- `plain()` before every host-owned sink the plugin cannot pin.
- No shell string. No `bash -c`, no `StdioCollector`, no `shell=True`, no `capture_output=True`.
- Absolute binaries, `python3 -I -S`, `clearEnvironment: true`, minimal environment.
- `--` before data arguments. IP, MAC, and port values are checked against an anchored pattern immediately before `exec`.
- Producer-side byte caps, absolute deadlines, process groups, TERM then KILL. Generation numbers discard stale completions.
- State and export writes are exclusive, 0600, fsync, rename. Reads of files we did not just create use one `O_NOFOLLOW|O_NONBLOCK` descriptor and a `cap + 1` read.
- No `/tmp` path and no `XDG_RUNTIME_DIR:-/tmp` fallback.
- No network fetch, no `curl`, no redirect, no configurable URL. ICMP, TCP connect, UDP port 9, and the local resolvers are the only packets.
- IPC is parameterless. `status` is small. Loading the plugin does not mutate config or start a scan.
- No `AGENTS.md`, `CLAUDE.md`, `.claude`, `.codex`, `.agents`, or `SKILL.md` in the tree. The scaffold's repository template is not used, because it ships `AGENTS.md`. Use the minimal plugin generator, then delete any agent-instruction file it still emits.
- No file over 512 KiB in the repo, no NUL in source, no bundled executable. `preview.png` can wait until a marketplace submission; do not add `setup.png` or any image whose name contains install, setup, or uninstall.
- README lists every command, the hwdata path, the state path, the Downloads files, the removal command, and the fact that the hotkey is manual. It does not say "no files are written" and it does not say the plugin edits Hyprland.

## Tests

`tests/run` covers, without root and without a live scan:

- Range parser accepts a host, a `/24`, and a bounded start-end pair, and rejects hostnames, IPv6, a `/16`, a leading dash, and 1025 addresses.
- State helper: symlink at the state path is not followed; a FIFO open does not hang; a file over the cap is rejected; `ENOENT` is distinct from a rejected file; the written file is mode 0600.
- A hostname and a vendor containing `<img src="http://127.0.0.1/x">` are stored and would be displayed only as plain text. The QML audit script reports no `Text` missing `textFormat`, and no `TextField`, `TextArea`, `TextInput`, or `TextEdit`.
- CSV formula prefixes.
- The scan verb's stdout line cap and the 1024-host refusal, using a fake `ping` on `PATH` inside the test process only. The production helper still execs `/usr/bin/ping` and ignores `PATH`.
- `omarchy plugin validate` on the tree when the host has the command. The CUA VM is the live check: bar widget, dropdown, floating window, Super+Alt+N, keyboard keys, copy, filters, persistence with timestamp, export, presets, Wake-on-LAN packet construction (the packet bytes, not a mandatory sleeping target), and cancel.

## What is left to the builder

- The exact `ping` and `nc` argument vectors after reading those binaries on the Omarchy 4.5 VM. The timeouts, numeric mode, and "no shell" rule do not move.
- Spacing, type size, and empty-state wording inside the Omarchy tokens and the `en.json` catalog.
- How the Python pool is scheduled, as long as the caps, the process group, and the deadlines stay.

## Out of scope for the first build

- Translations beyond English.
- A marketplace issue, a git push, and a GitHub repository. Those wait for the user's approval of the running plugin.
- Editing the host machine's Hyprland config. The binding is added only inside the CUA VM for the live test.
