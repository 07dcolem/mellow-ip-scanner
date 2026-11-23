import importlib.util
import json
import os
import select
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mellow_scan", ROOT / "bin" / "scan.py")
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


def write_script(directory, name, body):
    path = directory / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o700)
    return str(path)


class RangeTests(unittest.TestCase):
    def test_accepts_host_cidr_and_span(self):
        self.assertEqual(scan.expand_range("192.0.2.10")[1], ["192.0.2.10"])
        raw, hosts = scan.expand_range("192.0.2.0/24")
        self.assertEqual(raw, "192.0.2.0/24")
        self.assertEqual(len(hosts), 254)
        self.assertNotIn("192.0.2.0", hosts)
        self.assertNotIn("192.0.2.255", hosts)
        self.assertEqual(scan.expand_range("192.0.2.1-192.0.2.3")[1], ["192.0.2.1", "192.0.2.2", "192.0.2.3"])

    def test_rejects_unsafe_ranges(self):
        for text in ("gateway.example", "2001:db8::1", "10.0.0.0/16", "-192.0.2.1", "192.0.2.1;id", "127.0.0.1", "169.254.1.1"):
            with self.assertRaises(scan.ScanError):
                scan.expand_range(text)
        start = 0x0A000000
        end = start + 1024
        text = "%s-%s" % (scan.ipaddress.IPv4Address(start), scan.ipaddress.IPv4Address(end))
        with self.assertRaises(scan.ScanError):
            scan.expand_range(text)


class StateTests(unittest.TestCase):
    def sample(self):
        return {
            "scannedAt": "2026-11-22T14:03:00Z",
            "range": "192.0.2.0/30",
            "total": 2,
            "done": 2,
            "alive": 1,
            "partial": False,
            "hosts": [{
                "ip": "192.0.2.1",
                "alive": True,
                "ms": 4,
                "mac": "00:00:5e:00:00:01",
                "vendor": "Documentation",
                "hostname": "gateway.example",
                "hostnameSource": "dns",
                "ports": [80],
            }, {
                "ip": "192.0.2.2",
                "alive": False,
                "ms": None,
                "mac": "",
                "vendor": "",
                "hostname": "",
                "hostnameSource": "",
                "ports": [],
            }],
        }

    def test_demo_fixture_matches_the_saved_scan_schema(self):
        document = json.loads((ROOT / "demo" / "fixtures" / "example.json").read_text(encoding="utf-8"))
        loaded = scan.validate_document(document)
        self.assertEqual(loaded["range"], "192.0.2.0/24")
        self.assertEqual(loaded["alive"], 6)
        self.assertTrue(all(host["ip"].startswith("192.0.2.") for host in loaded["hosts"]))

    def test_round_trip_mode_and_rejections(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            self.assertIsNone(scan.load_state(home))
            scan.store_state(home, self.sample())
            path = home / ".local" / "state" / "mellow-ip-scan" / "last-scan.json"
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(scan.load_state(home)["alive"], 1)
            path.write_bytes(b"x" * (scan.MAX_STATE + 1))
            os.chmod(path, 0o600)
            with self.assertRaises(scan.ScanError):
                scan.load_state(home)
            path.unlink()
            self.assertIsNone(scan.load_state(home))

    def test_symlink_write_does_not_follow(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            victim = home / "victim"
            victim.write_text("must survive", encoding="utf-8")
            scan.store_state(home, self.sample())
            state = home / ".local" / "state" / "mellow-ip-scan" / "last-scan.json"
            state.unlink()
            state.symlink_to(victim)
            scan.store_state(home, self.sample())
            self.assertEqual(victim.read_text(encoding="utf-8"), "must survive")
            self.assertFalse(state.is_symlink())
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)

    def test_fifo_read_does_not_hang(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            scan.store_state(home, self.sample())
            state = home / ".local" / "state" / "mellow-ip-scan" / "last-scan.json"
            state.unlink()
            os.mkfifo(state)
            signal.alarm(2)
            try:
                self.assertIsNone(scan.load_state(home))
            finally:
                signal.alarm(0)
            self.assertFalse(state.exists())


class TextTests(unittest.TestCase):
    def test_markup_hostname_is_unresolved(self):
        self.assertEqual(scan.accept_hostname('<img src="http://127.0.0.1/x">'), "")
        self.assertEqual(scan.accept_vendor("ACME <b>Corp</b>"), "ACME bCorp/b")

    def test_csv_formula_prefix(self):
        self.assertTrue(scan.csv_cell("=cmd").startswith('"\''))
        self.assertTrue(scan.csv_cell("+1").startswith('"\''))
        self.assertIn('""', scan.csv_cell('say "hi"'))


class ScanTests(unittest.TestCase):
    def test_fake_ping_and_absolute_default(self):
        self.assertEqual(scan.PING_BIN, "/usr/bin/ping")
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            ping = write_script(directory, "ping", """\
                #!/usr/bin/python3
                import sys
                ip = sys.argv[-1]
                if ip.endswith(".1"):
                    print("64 bytes from %s: icmp_seq=1 ttl=64 time=1.25 ms" % ip)
                    raise SystemExit(0)
                raise SystemExit(1)
            """)
            getent = write_script(directory, "getent", """\
                #!/usr/bin/python3
                import sys
                ip = sys.argv[-1]
                if ip.endswith(".1"):
                    print("%s gateway.example" % ip)
                raise SystemExit(0)
            """)
            oui = directory / "oui.txt"
            oui.write_text("00005E     (base 16)            Documentation Network\n", encoding="utf-8")
            arp = directory / "arp"
            arp.write_text("192.0.2.1 0x1 0x2 00:00:5e:00:00:01 * eth0\n", encoding="utf-8")
            lines = []
            doc = scan.scan_hosts(
                "192.0.2.1-192.0.2.2",
                "80",
                False,
                ping_bin=ping,
                nc_bin="",
                getent_bin=getent,
                avahi_bin="",
                ip_bin="/no/such/ip",
                oui_path=str(oui),
                arp_path=str(arp),
                emit_fn=lines.append,
            )
            self.assertEqual(doc["alive"], 1)
            live = [row for row in doc["hosts"] if row["alive"]][0]
            self.assertEqual(live["ms"], 1)
            self.assertEqual(live["hostname"], "gateway.example")
            self.assertEqual(live["hostnameSource"], "dns")
            self.assertEqual(live["mac"], "00:00:5e:00:00:01")
            self.assertEqual(live["vendor"], "Documentation Network")
            self.assertTrue(all(len(json.dumps(line, separators=(",", ":"))) <= 1024 for line in lines))

    def test_output_cap_rejects_a_flood(self):
        with tempfile.TemporaryDirectory() as tmp:
            flood = write_script(Path(tmp), "flood", """\
                #!/usr/bin/python3
                print("x" * 20000)
            """)
            with self.assertRaises(scan.ScanError):
                scan.run_capped([flood], 2, 1024)

    def test_cli_refuses_a_wide_range_without_ping(self):
        proc = subprocess.Popen(
            [sys.executable, "-I", "-S", str(ROOT / "bin" / "scan.py"), "scan"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        proc.stdin.write(b'{"range":"10.0.0.0/16"}\n')
        proc.stdin.close()
        ready, _, _ = select.select([proc.stdout], [], [], 5)
        self.assertTrue(ready)
        out = os.read(proc.stdout.fileno(), 4096)
        proc.stdout.close()
        self.assertEqual(proc.wait(timeout=2), 1)
        self.assertIn(b"1024", out)


class DetectTests(unittest.TestCase):
    def test_prefers_a_private_lan_over_a_tunnel_and_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            ip = write_script(Path(tmp), "ip", """\
                #!/usr/bin/python3
                import sys
                args = sys.argv[1:]
                if "route" in args:
                    print('[{"dst":"default","dev":"tun0","prefsrc":"10.8.0.2","gateway":"10.8.0.1"}]')
                else:
                    print('[{"ifname":"tun0","addr_info":[{"family":"inet","local":"10.8.0.2","prefixlen":32}]},{"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":24}]},{"ifname":"eth0","addr_info":[{"family":"inet","local":"10.1.0.8","prefixlen":16}]},{"ifname":"wlan0","addr_info":[{"family":"inet","local":"192.168.4.20","prefixlen":24}]}]')
                raise SystemExit(0)
            """)
            self.assertEqual(scan.detect_range(ip), "192.168.4.0/24")

    def test_prefers_the_default_route_lan(self):
        with tempfile.TemporaryDirectory() as tmp:
            ip = write_script(Path(tmp), "ip", """\
                #!/usr/bin/python3
                import sys
                args = sys.argv[1:]
                if "route" in args:
                    print('[{"dst":"default","dev":"wlan0","prefsrc":"192.168.1.20","gateway":"192.168.1.1"}]')
                else:
                    print('[{"ifname":"eth0","addr_info":[{"family":"inet","local":"10.20.0.4","prefixlen":24}]},{"ifname":"wlan0","addr_info":[{"family":"inet","local":"192.168.1.20","prefixlen":24}]}]')
                raise SystemExit(0)
            """)
            self.assertEqual(scan.detect_range(ip), "192.168.1.0/24")


class PacketTests(unittest.TestCase):
    def test_magic_packet_and_broadcast(self):
        packet = scan.magic_packet("00:00:5E:00:00:01")
        self.assertEqual(packet[:6], b"\xff" * 6)
        self.assertEqual(len(packet), 102)
        self.assertEqual(packet[6:12], bytes.fromhex("00005e000001"))
        self.assertEqual(scan.broadcast_of("192.0.2.0/24"), "192.0.2.255")
        with self.assertRaises(scan.ScanError):
            scan.magic_packet("not-a-mac")


class ToolTests(unittest.TestCase):
    def test_names_only_the_missing_pieces(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            present = root / "bin"
            present.mkdir()
            for name in ("ping", "ip", "getent", "nc", "wl-copy", "avahi-resolve-address"):
                path = present / name
                path.write_text("#!/bin/sh\n", encoding="utf-8")
                path.chmod(0o755)
            oui = root / "oui.txt"
            oui.write_text("00:00:5E\n", encoding="utf-8")
            arp = root / "arp"
            arp.write_text("IP address\n", encoding="utf-8")
            bins = [str(present / name) for name in ("ping", "ip", "getent", "nc", "wl-copy", "avahi-resolve-address")]
            self.assertEqual(scan.tool_gaps(
                ping=bins[0], ip_bin=bins[1], arp=str(arp), oui=str(oui),
                nc_bins=(bins[3],), getent=bins[2], avahi_bins=(bins[5],), copy=bins[4],
            ), [])
            self.assertEqual(scan.tool_gaps(
                ping=bins[0], ip_bin=str(root / "missing-ip"), arp=str(arp), oui=str(root / "no-oui"),
                nc_bins=(str(root / "missing-nc"),), getent=bins[2], avahi_bins=(bins[5],), copy=bins[4],
            ), ["hwdata", "nc"])
            self.assertEqual(scan.tool_gaps(
                ping=bins[0], ip_bin=bins[1], arp=str(arp), oui=str(oui),
                nc_bins=(bins[3],), getent=str(root / "missing-getent"),
                avahi_bins=(str(root / "missing-avahi"),), copy=bins[4],
            ), ["names"])
            self.assertEqual(scan.tool_gaps(
                ping=bins[0], ip_bin=bins[1], arp=str(arp), oui=str(oui),
                nc_bins=(bins[3],), getent=bins[2], avahi_bins=(str(root / "missing-avahi"),), copy=bins[4],
            ), ["mdns"])
            self.assertEqual(scan.tool_gaps(
                ping=bins[0], ip_bin=str(root / "missing-ip"), arp=str(root / "missing-arp"),
                oui=str(oui), nc_bins=(bins[3],), getent=bins[2], avahi_bins=(bins[5],), copy=bins[4],
            ), ["ip"])


class HotkeyTests(unittest.TestCase):
    def test_appends_only_the_fixed_block(self):
        original = b"-- keep this line\n"
        state, rendered = scan.render_panel_hotkey_bytes(original)
        self.assertEqual(state, "set")
        self.assertTrue(rendered.startswith(original))
        self.assertTrue(rendered.endswith(scan.HOTKEY_BLOCK.encode("ascii")))
        text = rendered.decode("ascii")
        self.assertEqual(scan.classify_bindings(text), "ours")
        self.assertEqual(text.count("SUPER + ALT + N"), 1)
        self.assertNotIn("toggleWindow", text)
        again, extra = scan.render_panel_hotkey_bytes(rendered)
        self.assertEqual(again, "ours")
        self.assertIsNone(extra)

    def test_refuses_a_taken_or_edited_block(self):
        self.assertEqual(scan.classify_bindings('o.bind("SUPER + ALT + N", "Other", "true")\n'), "taken")
        self.assertEqual(scan.classify_bindings("-- remember SUPER + ALT + N\n"), "taken")
        self.assertEqual(scan.classify_bindings(scan.HOTKEY_BLOCK + scan.HOTKEY_BLOCK), "broken")
        mutated = scan.HOTKEY_BLOCK.replace("Mellow IP Scan", "Other")
        self.assertEqual(scan.classify_bindings(mutated), "broken")
        self.assertEqual(scan.classify_bindings("plain\n"), "free")

    def test_live_chord_does_not_override_our_block(self):
        self.assertEqual(scan.combine_hotkey("free", True), "taken")
        self.assertEqual(scan.combine_hotkey("ours", True), "ours")
        self.assertEqual(scan.combine_hotkey("free", False), "free")
        self.assertTrue(scan.binds_include_panel_chord(
            json.dumps([{"key": "N", "modmask": scan.PANEL_CHORD_MASK, "submap": ""}])
        ))
        self.assertFalse(scan.binds_include_panel_chord(
            json.dumps([{"key": "N", "modmask": 68, "submap": "", "description": "Network"}])
        ))
        with self.assertRaises(scan.ScanError):
            scan.binds_include_panel_chord(b"not-json")

    def test_shared_write_keeps_mode_and_refuses_a_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                name = "bindings.lua"
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644, dir_fd=directory)
                os.write(fd, b"-- keep\n")
                os.close(fd)
                blob, mode = scan.read_shared(directory, name, scan.MAX_BINDINGS)
                self.assertEqual(blob, b"-- keep\n")
                self.assertEqual(mode, 0o644)
                scan.write_shared(directory, name, blob + b"next\n", mode, scan.MAX_BINDINGS)
                blob, mode = scan.read_shared(directory, name, scan.MAX_BINDINGS)
                self.assertEqual(blob, b"-- keep\nnext\n")
                self.assertEqual(mode, 0o644)
                os.chmod(os.path.join(tmp, name), 0o666)
                with self.assertRaises(scan.ScanError):
                    scan.read_shared(directory, name, scan.MAX_BINDINGS)
                os.unlink(name, dir_fd=directory)
                os.symlink("elsewhere", name, dir_fd=directory)
                with self.assertRaises(scan.ScanError):
                    scan.read_shared(directory, name, scan.MAX_BINDINGS)
            finally:
                os.close(directory)


if __name__ == "__main__":
    unittest.main()
