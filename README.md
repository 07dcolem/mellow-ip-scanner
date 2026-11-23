# Mellow IP Scan

Keyboard-first local IPv4 scanner for the Omarchy bar. The bar shows how many hosts answered. The dropdown and a separate window show the same result.

![Mellow IP Scan showing a fictional scan of 192.0.2.0/24](preview.png)

Left click opens the dropdown. Middle click starts or stops. Right click detects the subnet again. The first time you open it, if no range is saved, it picks one: the network on the default route when that network is a sensible size, otherwise another private LAN. Tunnel, container, and point-to-point addresses are skipped.

Inside the dropdown, `v` or Open full (v) opens a window titled Mellow IP Scan and closes the dropdown. The window has no global key. Closing either surface leaves a running scan alone.

The last-scan line uses the same date and time pattern as the clock on the bar. It keeps this panel's own type.

## Install

```bash
omarchy plugin add https://github.com/07dcolem/mellow-ip-scanner.git --enable
```

`omarchy plugin add` clones the current default branch. It does not install one reviewed commit. The command asks you to confirm the repository, then which side of the bar to use. Right is the default.

To move it later:

```bash
omarchy plugin enable io.github.07dcolem.mellow-ip-scan --section right
```

The service stays loaded. If the button does not appear, or after you update the plugin, restart the shell:

```bash
omarchy restart shell
```

Update a git install with:

```bash
omarchy plugin update io.github.07dcolem.mellow-ip-scan
```

No sudo or pkexec is required. The plugin does not install packages and does not download anything.

From a local checkout, while that directory is the tree you want the shell to load:

```bash
mkdir -p ~/.config/omarchy/plugins
rm -rf ~/.config/omarchy/plugins/io.github.07dcolem.mellow-ip-scan
cp -a . ~/.config/omarchy/plugins/io.github.07dcolem.mellow-ip-scan
omarchy plugin enable io.github.07dcolem.mellow-ip-scan --section right
omarchy restart shell
```

## What a scan does

Host discovery is ICMP via `/usr/bin/ping`. One scan covers at most 1024 addresses. A `/24` and a `/22` fit. Anything larger is refused before a ping is sent.

TCP checks are off until you turn them on. The default ports are 22, 80, 443, 445, 3389, and 9100. Checks use `/usr/bin/nc` or `/usr/bin/openbsd-nc` with a one-second timeout, and only on hosts that answered ping. If neither binary is installed, the scan still runs and the panel says: For open ports, install openbsd-netcat.

For each live host the scanner stores round-trip time, the MAC address from `/proc/net/arp` or `/usr/bin/ip neigh`, a vendor name from `/usr/share/hwdata/oui.txt` when that file is present, and a hostname from `/usr/bin/getent hosts`, then mDNS when `avahi-resolve-address` or `avahi-resolve` exists. Open ports are stored only when TCP checks are on and `nc` is installed.

The address is always the first column, wide enough for a full IPv4 address. Name, latency, MAC, vendor, ports, and name source follow in the order you set under Options. A column appears only when the row is wide enough for it. The MAC column is wide enough for a full address; when it does not fit, that address stays on the focused row instead of being cut off. Cell text that is still too long is elided. The list scrolls vertically only. There is no horizontal scrollbar.

An unresolved name is shown as a dash. If a column needs a program or data file that is not installed, the list and the options page say so. Nothing here fingerprints an operating system, enumerates SMB, or uses nmap, raw sockets, or root.

## Keyboard

| Key | Action |
| --- | --- |
| `j` / `k`, arrows | Move |
| Enter | Copy the focused IP |
| `s` | Start or stop |
| `r` | Detect the subnet again |
| `f` | Filters |
| `o` | Range, ports, columns, and presets |
| `c` `m` `n` | Copy IP, MAC, and hostname |
| `e` | Export the filtered view |
| `w` | Wake-on-LAN for the focused host |
| `v` | Open the full window, from the dropdown only |
| `x` | Lower the focused column, or remove the focused preset |
| Esc | Step back, then close |

`h` and `l` move left and right in every Omarchy panel, so hostname is `n`. Copy, export, wake, and re-detect keep a running scan going. `s` is what starts and stops it. Hosts stay in address order while results arrive.

Filters never start a new scan. Dead hosts are hidden until you show them. You can also hide hosts above a latency, keep only hosts with an open port, or match the IP, hostname, MAC, or vendor.

Range, ports, the filter text, the latency field, and a preset name are edited on a plain line. Click a field, or press Enter on it. Empty option fields show a gray example, such as `192.0.2.0/24` or `home`, until the field is clicked or the keyboard cursor moves onto it. That line does not read the clipboard.

## Mouse

Click a host to select it. Double-click it to copy the IP. Scan, Filters, Options, copy, Export, and Wake are buttons on the list. Click a preset to use its range. Remove deletes that preset. Re-detect subnet and Save preset are clickable rows.

When more hosts sit below the visible list, the bottom edge fades and a vertical scrollbar appears. The wheel, the scrollbar, and `j` / `k` move through the rows.

## Export, presets, and Wake-on-LAN

`e` writes the hosts currently on screen to `~/Downloads/mellow-ip-scan-YYYYMMDD-HHMMSS.csv` and `.txt`. The files are mode 0600. A spreadsheet formula prefix is quoted.

Presets, ports, column order, and filters are saved in this widget's entry in `~/.config/omarchy/shell.json` when you save, re-detect, or change a filter. At most eight presets are kept. Saving the same name again replaces that preset. `x` on a preset removes it.

Wake-on-LAN sends one UDP packet to port 9, to the broadcast address of the current range. The MAC has to be six hex bytes from the scan.

## Hotkey

The dropdown offers Super+Alt+N when that chord is free and you have not dismissed the offer. The offer sits under Open full and the host count. Set writes one marked block at the end of `~/.config/hypr/bindings.lua`, reloads Hyprland, and puts the previous file back if the reload reports a new config error. Nothing is written until you click Set Super+Alt+N. The x beside it saves that you do not want the offer. If the chord is already used, the button is not offered.

```lua
-- mellow-ip-scan: begin
o.bind("SUPER + ALT + N", "Mellow IP Scan", { panel = "io.github.07dcolem.mellow-ip-scan" })
-- mellow-ip-scan: end
```

That chord opens the dropdown, not the window. Super+Ctrl+N stays the Network panel.

## Requirements

Omarchy 4 with `omarchy-shell`. `/usr/bin/ping` and `/usr/bin/python3` are required. These are used when they exist, and the scan still runs without them:

| Path | Used for |
| --- | --- |
| `/usr/share/hwdata/oui.txt` | Vendor names |
| `/usr/bin/nc` or `/usr/bin/openbsd-nc` | TCP checks. The package is `openbsd-netcat` |
| `/usr/bin/getent` and avahi | Hostnames |
| `/usr/bin/wl-copy` | Copy |
| `/usr/bin/ip` | Subnet detection and a second MAC lookup |

No sudo or pkexec is required. The only packets are ping, the optional TCP connects, UDP port 9, and the local resolvers.

## Files

| Path | What it is |
| --- | --- |
| `~/.config/omarchy/shell.json` | Range, ports, filters, column order, presets, and whether the hotkey offer was dismissed, on this widget's entry |
| `~/.local/state/mellow-ip-scan/last-scan.json` | Last scan, including the time it finished. Mode 0600 |
| `~/Downloads/mellow-ip-scan-*.csv` and `.txt` | Exports you asked for |

The state directory is created when a scan finishes or you export. Opening the panel does not start a scan.

## Removing

```bash
omarchy plugin remove io.github.07dcolem.mellow-ip-scan
```

That removes the plugin and its bar entry. It does not delete `~/.local/state/mellow-ip-scan/`, files already written under `~/Downloads/`, or a hotkey block in `~/.config/hypr/bindings.lua`. Those stay until you delete them. The hotkey block is the three lines between `-- mellow-ip-scan: begin` and `-- mellow-ip-scan: end`. No background process is left running.

## Development

```bash
./tests/run
```

The tests do not ping the network. They use stand-in programs and the documentation prefix `192.0.2.0/24`. The screenshot above is that same prefix, loaded through a reversible stand-in scan, not a scan of a real LAN.

License: MIT. Copyright (c) 2026 Dylan Coleman.
