# Changelog

## 0.1.2

- Setting Super+Alt+N reads `bindings.lua` again after the Hyprland checks and appends the marked block to that current file.
- If the reload reports a new config error, only that marked block is removed. Bindings saved while the check was running stay in the file.

## 0.1.1

- The filter text and the latency line show the keyboard cursor.
- Filters Back returns to the host you left, the same as Esc and Back on Options.
- Copy and Wake use that host from Filters and Options.
- On the dropdown, `b` sets Super+Alt+N while the offer is showing. `x` on the host list dismisses the offer. Nothing is written until `b` or the Set button.

## 0.1.0

- First release of Mellow IP Scan.
- Ping discovery for up to 1024 addresses, with optional TCP checks on 22, 80, 443, 445, 3389, and 9100.
- MAC address, vendor from the system hwdata file, hostname from DNS and mDNS, and latency.
- Bar widget, keyboard dropdown, and a separate window. The dropdown can set Super+Alt+N to open the dropdown. The window has no global key.
- Filters, copy, CSV and text export, range presets, Wake-on-LAN, and a saved last scan with its time.
- Copy, export, wake, and re-detect no longer cancel a scan that is already running.
- The host list stays in address order, and the highlight follows the host you moved to.
- Saving a preset name again updates it. `x` removes the focused preset.
- A missing settings key no longer resets the other options. Port-check and preset status messages clear on their own.
- Fields, presets, and the main actions accept the mouse. The dropdown title row has Open full (v).
- The first launch detects a sensible subnet when none is saved. Empty option fields show a gray example until they are clicked or selected.
- A fade and a scrollbar show when the host list continues below the dropdown or the window. The window list uses the height the window has.
- The key hint line stays fully visible when the window is maximized.
- Name, latency, MAC, vendor, ports, and name source appear as columns when the row is wide enough. Options sets which of those come first. A missing program for one of them stays on screen as a warning.
- The open-port warning names the package to install, `openbsd-netcat`.
- The dropdown title row has Open full (v). `v` opens the full window. The dropdown can set Super+Alt+N to open the dropdown. The full window has no global key.
- The Super+Alt+N offer sits under Open full and the host count. Its x hides the offer and does not ask again.
- The last scan time uses the bar clock's date and time pattern.
- The action buttons and the key hints stay on one line in a narrow window.
- The IP and MAC columns are wide enough for a full address. A MAC that does not fit is left off the row and shown on the focused host.
