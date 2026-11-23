#!/usr/bin/python3 -I
"""Bounded local scanner for Mellow IP Scan.

The shell starts this as `/usr/bin/python3 -I -S bin/scan.py <verb>`.
Request bodies arrive as one JSON line on stdin. Results leave as short
JSON lines on stdout. Addresses, MACs, and ports are checked again here
before any program runs.
"""

import datetime
import errno
import ipaddress
import json
import os
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

MAX_HOSTS = 1024
MAX_LINE = 1024
MAX_STATE = 512 * 1024
MAX_REQUEST = 8192
MAX_EXPORT = 512 * 1024
MAX_OUI = 16 * 1024 * 1024
MAX_ARP = 256 * 1024
MAX_PORTS = 8
VENDOR_CAP = 64
HOST_CAP = 253
COPY_CAP = 512
POOL_DEFAULT = 32
POOL_MAX = 64
SCAN_DEADLINE = 180
STATE_NAME = "last-scan.json"
PLUGIN_PARTS = (".local", "state", "mellow-ip-scan")
PING_BIN = "/usr/bin/ping"
GETENT_BIN = "/usr/bin/getent"
IP_BIN = "/usr/bin/ip"
WL_COPY_BIN = "/usr/bin/wl-copy"
OUI_PATH = "/usr/share/hwdata/oui.txt"
ARP_PATH = "/proc/net/arp"
NC_CANDIDATES = ("/usr/bin/nc", "/usr/bin/openbsd-nc")
AVAHI_CANDIDATES = ("/usr/bin/avahi-resolve-address", "/usr/bin/avahi-resolve")

_COMPONENT = re.compile(r"[A-Za-z0-9._-]+")
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_STAMP = re.compile(r"^\d{8}-\d{6}$")
_WHEN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HOST = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_TIME = re.compile(r"time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms")
_OUI_LINE = re.compile(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+?)\s*$")
_CONTROLS = set(range(32)) | set(range(0x7F, 0xA0))


class ScanError(Exception):
    pass


SESSION = {"WAYLAND_DISPLAY": "", "XDG_RUNTIME_DIR": "", "HYPRLAND_INSTANCE_SIGNATURE": ""}


def capture_session():
    display = os.environ.get("WAYLAND_DISPLAY", "")
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    signature = os.environ.get("HYPRLAND_INSTANCE_SIGNATURE", "")
    if re.fullmatch(r"wayland-[0-9]+", display):
        SESSION["WAYLAND_DISPLAY"] = display
    if re.fullmatch(r"/run/user/[0-9]+", runtime):
        SESSION["XDG_RUNTIME_DIR"] = runtime
    # Hyprland's instance id is one directory name: commit, time, and a number.
    if re.fullmatch(r"[0-9a-f]{7,64}_[0-9]{1,16}_[0-9]{1,16}", signature):
        SESSION["HYPRLAND_INSTANCE_SIGNATURE"] = signature


def scrub_environ():
    os.environ.clear()
    os.environ["PATH"] = "/usr/bin"
    os.environ["LC_ALL"] = "C"


def emit(obj):
    line = json.dumps(obj, separators=(",", ":"), ensure_ascii=True)
    if len(line.encode("ascii")) > MAX_LINE:
        raise ScanError("result line exceeds 1024 bytes")
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def fail(message):
    text = sanitize_text(message, 160)
    emit({"t": "error", "error": text or "scan failed"})
    return 1


def sanitize_text(value, limit):
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    out = []
    for char in value:
        code = ord(char)
        if code in _CONTROLS or code in (0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
            continue
        if char in "<>&":
            continue
        out.append(char)
        if len(out) >= limit:
            break
    return "".join(out).strip()


def accept_hostname(value):
    text = sanitize_text(value, HOST_CAP)
    if not text or len(text) > HOST_CAP or not _HOST.fullmatch(text):
        return ""
    return text


def accept_vendor(value):
    return sanitize_text(value, VENDOR_CAP)


def accept_mac(value):
    text = sanitize_text(value, 17).lower().replace("-", ":")
    if not _MAC.fullmatch(text) or text == "00:00:00:00:00:00":
        return ""
    return text


def allowed_host(ip):
    if not isinstance(ip, ipaddress.IPv4Address):
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        return False
    if int(ip) >= int(ipaddress.IPv4Address("240.0.0.0")):
        return False
    return True


def parse_ip(text):
    try:
        ip = ipaddress.IPv4Address(text)
    except (ipaddress.AddressValueError, ValueError):
        raise ScanError("invalid address")
    if not allowed_host(ip):
        raise ScanError("address is not scannable")
    return ip


def expand_range(text):
    if not isinstance(text, str):
        raise ScanError("range must be text")
    raw = text.strip()
    if not raw or len(raw) > 64 or raw[:1] == "-" or any(ord(char) < 33 for char in raw):
        raise ScanError("invalid range")
    if "/" in raw:
        try:
            network = ipaddress.IPv4Network(raw, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            raise ScanError("invalid range")
        if network.num_addresses > MAX_HOSTS:
            raise ScanError("range exceeds 1024 addresses")
        if network.prefixlen >= 31:
            hosts = [ip for ip in network if allowed_host(ip)]
        else:
            hosts = [ip for ip in network.hosts() if allowed_host(ip)]
    elif "-" in raw:
        start_text, end_text = raw.split("-", 1)
        start, end = parse_ip(start_text), parse_ip(end_text)
        count = int(end) - int(start) + 1
        if count < 1 or count > MAX_HOSTS:
            raise ScanError("range exceeds 1024 addresses")
        hosts = []
        for offset in range(count):
            ip = ipaddress.IPv4Address(int(start) + offset)
            if allowed_host(ip):
                hosts.append(ip)
    else:
        hosts = [parse_ip(raw)]
    if not hosts or len(hosts) > MAX_HOSTS:
        raise ScanError("range exceeds 1024 addresses")
    return raw, [str(ip) for ip in hosts]


def parse_ports(value):
    if value is None or value == "":
        return []
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, list):
        items = value
    else:
        raise ScanError("invalid port list")
    if len(items) > MAX_PORTS:
        raise ScanError("at most 8 ports")
    ports = []
    for item in items:
        if isinstance(item, bool) or isinstance(item, float):
            raise ScanError("invalid port")
        if isinstance(item, int):
            number = item
        elif isinstance(item, str) and re.fullmatch(r"[0-9]{1,5}", item):
            number = int(item)
        else:
            raise ScanError("invalid port")
        if number < 1 or number > 65535:
            raise ScanError("invalid port")
        if number not in ports:
            ports.append(number)
    return ports


def broadcast_of(range_text):
    raw, _hosts = expand_range(range_text)
    if "/" in raw:
        return str(ipaddress.IPv4Network(raw, strict=False).broadcast_address)
    first = _hosts[0]
    parts = first.split(".")
    return ".".join(parts[:3] + ["255"])


def magic_packet(mac):
    accepted = accept_mac(mac)
    if not accepted:
        raise ScanError("invalid MAC address")
    raw = bytes(int(part, 16) for part in accepted.split(":"))
    return b"\xff" * 6 + raw * 16


def _kill_group(pid, sig=signal.SIGTERM):
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            return


def run_capped(argv, timeout, max_bytes, err_max=4096, env=None):
    if not argv or not isinstance(argv[0], str) or not argv[0].startswith("/") or argv[0] == "/":
        raise ScanError("absolute command required")
    for arg in argv:
        if not isinstance(arg, str) or "\x00" in arg:
            raise ScanError("bad argument")
    child_env = {"PATH": "/usr/bin", "LC_ALL": "C"}
    if env:
        for key in ("XDG_RUNTIME_DIR", "WAYLAND_DISPLAY", "HYPRLAND_INSTANCE_SIGNATURE"):
            value = env.get(key)
            if isinstance(value, str) and value:
                child_env[key] = value
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=child_env,
    )
    deadline = time.monotonic() + timeout
    out = bytearray()
    err = bytearray()
    streams = [proc.stdout, proc.stderr]
    overflow = False
    timed_out = False
    try:
        while streams:
            remain = deadline - time.monotonic()
            if remain <= 0:
                timed_out = True
                break
            ready, _, _ = select.select(streams, [], [], min(remain, 0.2))
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            for stream in list(ready):
                if stream not in streams:
                    continue
                chunk = os.read(stream.fileno(), 65536)
                target = out if stream is proc.stdout else err
                limit = max_bytes if stream is proc.stdout else err_max
                if not chunk:
                    streams.remove(stream)
                    continue
                target.extend(chunk)
                if len(target) > limit:
                    overflow = True
                    streams = []
                    break
        if proc.poll() is None:
            _kill_group(proc.pid)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                _kill_group(proc.pid, signal.SIGKILL)
                proc.wait(timeout=2)
        else:
            proc.wait(timeout=1)
    finally:
        if proc.poll() is None:
            _kill_group(proc.pid, signal.SIGKILL)
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass
    if overflow:
        raise ScanError("output exceeded limit")
    if timed_out:
        return 124, bytes(out), bytes(err)
    return proc.returncode if proc.returncode is not None else 1, bytes(out), bytes(err)


def _decode(blob, limit):
    return blob[:limit].decode("utf-8", "replace")


def ping_host(ip, ping_bin):
    code, out, _err = run_capped([ping_bin, "-n", "-c", "1", "-W", "1", "-w", "2", "--", ip], 3, 4096)
    if code != 0:
        return None
    match = _TIME.search(_decode(out, 4096))
    if not match:
        return 0
    try:
        millis = int(round(float(match.group(1))))
    except ValueError:
        return 0
    if millis < 0 or millis > 10000:
        return None
    return millis


def read_arp_table(path):
    found = {}
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return found
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return found
        os.set_blocking(fd, True)
        blob = b""
        while len(blob) <= MAX_ARP:
            chunk = os.read(fd, min(65536, MAX_ARP + 1 - len(blob)))
            if not chunk:
                break
            blob += chunk
        if len(blob) > MAX_ARP:
            return {}
    finally:
        os.close(fd)
    for line in blob.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        mac = accept_mac(parts[3])
        if not mac:
            continue
        try:
            ip = str(parse_ip(parts[0]))
        except ScanError:
            continue
        found[ip] = mac
    return found


def read_neigh(ip_bin):
    found = {}
    if not os.path.isfile(ip_bin) or os.path.islink(ip_bin):
        return found
    try:
        code, out, _err = run_capped([ip_bin, "-4", "neigh", "show"], 2, 65536)
    except ScanError:
        return found
    if code not in (0, 124):
        return found
    for line in _decode(out, 65536).splitlines():
        parts = line.split()
        if "lladdr" not in parts:
            continue
        index = parts.index("lladdr")
        if index + 1 >= len(parts):
            continue
        mac = accept_mac(parts[index + 1])
        if not mac:
            continue
        try:
            ip = str(parse_ip(parts[0]))
        except ScanError:
            continue
        found[ip] = mac
    return found


def lookup_vendor(mac, oui_path, cache):
    accepted = accept_mac(mac)
    if not accepted:
        return ""
    prefix = accepted.replace(":", "")[:6].upper()
    if prefix in cache:
        return cache[prefix]
    vendor = ""
    try:
        fd = os.open(oui_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        cache[prefix] = ""
        return ""
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_OUI:
            cache[prefix] = ""
            return ""
        os.set_blocking(fd, True)
        carry = b""
        seen = 0
        while seen <= MAX_OUI:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            seen += len(chunk)
            if seen > MAX_OUI:
                break
            blob = carry + chunk
            lines = blob.split(b"\n")
            carry = lines[-1]
            for raw in lines[:-1]:
                match = _OUI_LINE.match(raw.decode("ascii", "ignore"))
                if match and match.group(1) == prefix:
                    vendor = accept_vendor(match.group(2))
                    cache[prefix] = vendor
                    return vendor
        if carry:
            match = _OUI_LINE.match(carry.decode("ascii", "ignore"))
            if match and match.group(1) == prefix:
                vendor = accept_vendor(match.group(2))
    finally:
        os.close(fd)
    if len(cache) > 512:
        cache.clear()
    cache[prefix] = vendor
    return vendor


def lookup_hostname(ip, getent_bin, avahi_bin):
    if os.path.isfile(getent_bin) and not os.path.islink(getent_bin):
        try:
            code, out, _err = run_capped([getent_bin, "hosts", ip], 2, 1024)
        except ScanError:
            code, out = 1, b""
        if code == 0:
            for line in _decode(out, 1024).splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip:
                    name = accept_hostname(parts[1])
                    if name and name != ip:
                        return name, "dns"
    if avahi_bin and os.path.isfile(avahi_bin) and not os.path.islink(avahi_bin):
        argv = [avahi_bin, ip] if avahi_bin.endswith("avahi-resolve-address") else [avahi_bin, "-a", ip]
        try:
            code, out, _err = run_capped(argv, 2, 1024)
        except ScanError:
            code, out = 1, b""
        if code == 0:
            for line in _decode(out, 1024).splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    name = accept_hostname(parts[-1])
                    if name and name != ip:
                        return name, "mdns"
    return "", ""


def open_ports(ip, ports, nc_bin):
    if not nc_bin:
        return []
    found = []
    for port in ports:
        code, _out, _err = run_capped([nc_bin, "-z", "-w", "1", "--", ip, str(port)], 2, 1024)
        if code == 0:
            found.append(port)
    return found


def which_first(candidates):
    for path in candidates:
        if os.path.isfile(path) and not os.path.islink(path):
            return path
    return ""


def _usable_file(path):
    return bool(path) and os.path.isfile(path) and not os.path.islink(path)


def tool_gaps(ping=PING_BIN, ip_bin=IP_BIN, arp=ARP_PATH, oui=OUI_PATH,
              nc_bins=NC_CANDIDATES, getent=GETENT_BIN, avahi_bins=AVAHI_CANDIDATES,
              copy=WL_COPY_BIN):
    """Names of installable pieces the scan cannot fill. Order is stable."""
    missing = []
    if not _usable_file(ping):
        missing.append("ping")
    if not _usable_file(ip_bin) and not _usable_file(arp):
        missing.append("ip")
    if not _usable_file(oui):
        missing.append("hwdata")
    if not which_first(nc_bins):
        missing.append("nc")
    has_getent = _usable_file(getent)
    has_avahi = bool(which_first(avahi_bins))
    if not has_getent and not has_avahi:
        missing.append("names")
    elif not has_avahi:
        missing.append("mdns")
    if not _usable_file(copy):
        missing.append("copy")
    return missing


def probe_host(ip, ports, port_checks, nc_bin, ping_bin, getent_bin, avahi_bin, arp, oui_path, oui_cache, lookup_slots):
    millis = ping_host(ip, ping_bin)
    if millis is None:
        return {
            "ip": ip, "alive": False, "ms": None, "mac": "", "vendor": "",
            "hostname": "", "hostnameSource": "", "ports": [],
        }
    with lookup_slots:
        mac = arp.get(ip, "")
        hostname, source = lookup_hostname(ip, getent_bin, avahi_bin)
        opened = open_ports(ip, ports, nc_bin) if port_checks else []
    vendor = lookup_vendor(mac, oui_path, oui_cache) if mac else ""
    return {
        "ip": ip,
        "alive": True,
        "ms": millis,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "hostnameSource": source if hostname else "",
        "ports": opened,
    }


def scan_hosts(range_text, ports, port_checks, ping_bin=PING_BIN, nc_bin=None, getent_bin=GETENT_BIN,
               avahi_bin=None, ip_bin=IP_BIN, oui_path=OUI_PATH, arp_path=ARP_PATH,
               concurrency=POOL_DEFAULT, deadline_s=SCAN_DEADLINE, emit_fn=None, stop=None):
    raw, hosts = expand_range(range_text)
    ports = parse_ports(ports)
    if not isinstance(port_checks, bool):
        raise ScanError("port checks must be on or off")
    workers = concurrency if isinstance(concurrency, int) and not isinstance(concurrency, bool) else POOL_DEFAULT
    if workers < 1:
        workers = 1
    if workers > POOL_MAX:
        workers = POOL_MAX
    if nc_bin is None and port_checks:
        nc_bin = which_first(NC_CANDIDATES)
    nc_note = ""
    if port_checks and not nc_bin:
        nc_note = "port checks need nc"
        port_checks = False
    if avahi_bin is None:
        avahi_bin = which_first(AVAHI_CANDIDATES)
    sender = emit_fn or emit
    stopper = stop or threading.Event()
    arp = {}
    arp.update(read_arp_table(arp_path))
    arp.update(read_neigh(ip_bin))
    oui_cache = {}
    lookup_slots = threading.BoundedSemaphore(8)
    results = []
    done = 0
    lock = threading.Lock()
    deadline = time.monotonic() + deadline_s

    def one(ip):
        if stopper.is_set() or time.monotonic() > deadline:
            return None
        try:
            return probe_host(ip, ports, port_checks, nc_bin, ping_bin, getent_bin, avahi_bin, arp, oui_path, oui_cache, lookup_slots)
        except ScanError:
            return {
                "ip": ip, "alive": False, "ms": None, "mac": "", "vendor": "",
                "hostname": "", "hostnameSource": "", "ports": [],
            }

    from concurrent.futures import ThreadPoolExecutor, as_completed
    executor = ThreadPoolExecutor(max_workers=workers)
    futures = []
    try:
        for ip in hosts:
            if stopper.is_set():
                break
            futures.append(executor.submit(one, ip))
        for future in as_completed(futures):
            if stopper.is_set() or time.monotonic() > deadline:
                stopper.set()
                break
            row = future.result()
            if row is None:
                continue
            with lock:
                done += 1
                results.append(row)
                current = done
            sender({"t": "progress", "done": current, "total": len(hosts)})
            sender({"t": "host", **row})
    finally:
        stopper.set()
        executor.shutdown(wait=False, cancel_futures=True)
    partial = done < len(hosts)
    results.sort(key=lambda row: tuple(int(part) for part in row["ip"].split(".")))
    alive = sum(1 for row in results if row["alive"])
    when = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    document = {
        "scannedAt": when,
        "range": raw,
        "total": len(hosts),
        "done": done,
        "alive": alive,
        "partial": partial,
        "hosts": results,
    }
    sender({
        "t": "done",
        "scannedAt": when,
        "done": done,
        "total": len(hosts),
        "alive": alive,
        "partial": partial,
        "note": nc_note,
    })
    return document


def _ok_component(name):
    return bool(_COMPONENT.fullmatch(name)) and name not in (".", "..")


def passwd_home():
    import pwd
    return pwd.getpwuid(os.geteuid()).pw_dir


def open_dir_chain(home, parts, lock_leaf=True, create=True):
    if not parts or not all(_ok_component(part) for part in parts):
        raise ScanError("refusing directory chain")
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, name in enumerate(parts):
            last = index == len(parts) - 1
            try:
                opened = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise ScanError("absent")
                os.mkdir(name, 0o700, dir_fd=fd)
                opened = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = opened
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise ScanError("untrusted directory")
            if last and lock_leaf and info.st_mode & 0o077:
                os.fchmod(fd, 0o700)
        return fd
    except BaseException:
        os.close(fd)
        raise


def repair_state_dir(dirfd):
    info = os.fstat(dirfd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise ScanError("untrusted state directory")
    if info.st_mode & 0o077:
        os.fchmod(dirfd, 0o700)
    for name in os.listdir("/proc/self/fd/%d" % dirfd):
        if name in (".", "..") or not _ok_component(name):
            continue
        opened = -1
        try:
            opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dirfd)
            st = os.fstat(opened)
            if not stat.S_ISREG(st.st_mode):
                os.close(opened)
                opened = -1
                os.unlink(name, dir_fd=dirfd)
                continue
            if st.st_uid == os.geteuid() and st.st_nlink == 1 and st.st_mode & 0o077:
                os.fchmod(opened, 0o600)
        except FileNotFoundError:
            continue
        except OSError as error:
            if error.errno == errno.ELOOP:
                try:
                    os.unlink(name, dir_fd=dirfd)
                except OSError:
                    pass
            continue
        finally:
            if opened >= 0:
                os.close(opened)


def read_bounded(dirfd, name, limit):
    if not _ok_component(name):
        raise ScanError("refusing state name")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dirfd)
    except FileNotFoundError:
        return None
    except OSError:
        raise ScanError("refusing state file")
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > limit):
            raise ScanError("refusing state file")
        os.set_blocking(fd, True)
        blob = b""
        while len(blob) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(blob)))
            if not chunk:
                break
            blob += chunk
        if len(blob) > limit:
            raise ScanError("state file exceeds limit")
        return blob
    finally:
        os.close(fd)


def write_atomic(dirfd, name, data):
    if not _ok_component(name) or len(data) > MAX_STATE:
        raise ScanError("refusing state write")
    import secrets
    tmp = ".%s.%s.tmp" % (name, secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dirfd)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ScanError("short write")
            view = view[written:]
        os.fsync(fd)
        os.rename(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        os.fsync(dirfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dirfd)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def _finite_int(value, low, high):
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return low <= value <= high


def validate_host(row):
    if not isinstance(row, dict) or set(row) != {"ip", "alive", "ms", "mac", "vendor", "hostname", "hostnameSource", "ports"}:
        raise ScanError("saved scan was rejected")
    if not isinstance(row["ip"], str):
        raise ScanError("saved scan was rejected")
    parse_ip(row["ip"])
    if not isinstance(row["alive"], bool):
        raise ScanError("saved scan was rejected")
    if row["ms"] is None:
        if row["alive"]:
            raise ScanError("saved scan was rejected")
    elif not _finite_int(row["ms"], 0, 10000):
        raise ScanError("saved scan was rejected")
    if row["mac"] != "" and accept_mac(row["mac"]) != row["mac"]:
        raise ScanError("saved scan was rejected")
    if not isinstance(row["vendor"], str) or row["vendor"] != accept_vendor(row["vendor"]):
        raise ScanError("saved scan was rejected")
    if not isinstance(row["hostname"], str) or (row["hostname"] and accept_hostname(row["hostname"]) != row["hostname"]):
        raise ScanError("saved scan was rejected")
    if row["hostnameSource"] not in ("", "dns", "mdns"):
        raise ScanError("saved scan was rejected")
    if row["hostnameSource"] and not row["hostname"]:
        raise ScanError("saved scan was rejected")
    if not isinstance(row["ports"], list) or len(row["ports"]) > MAX_PORTS:
        raise ScanError("saved scan was rejected")
    for port in row["ports"]:
        if not _finite_int(port, 1, 65535):
            raise ScanError("saved scan was rejected")
    return row


def validate_document(doc):
    if not isinstance(doc, dict):
        raise ScanError("saved scan was rejected")
    expected = {"scannedAt", "range", "total", "done", "alive", "partial", "hosts"}
    if set(doc) != expected:
        raise ScanError("saved scan was rejected")
    if not isinstance(doc["scannedAt"], str) or not _WHEN.fullmatch(doc["scannedAt"]):
        raise ScanError("saved scan was rejected")
    if not isinstance(doc["range"], str):
        raise ScanError("saved scan was rejected")
    expand_range(doc["range"])
    if not _finite_int(doc["total"], 0, MAX_HOSTS) or not _finite_int(doc["done"], 0, MAX_HOSTS):
        raise ScanError("saved scan was rejected")
    if not _finite_int(doc["alive"], 0, MAX_HOSTS) or not isinstance(doc["partial"], bool):
        raise ScanError("saved scan was rejected")
    if not isinstance(doc["hosts"], list) or len(doc["hosts"]) > MAX_HOSTS:
        raise ScanError("saved scan was rejected")
    for row in doc["hosts"]:
        validate_host(row)
    if doc["alive"] != sum(1 for row in doc["hosts"] if row["alive"]):
        raise ScanError("saved scan was rejected")
    return doc


def load_state(home):
    try:
        dirfd = open_dir_chain(home, PLUGIN_PARTS, lock_leaf=True, create=False)
    except ScanError as error:
        if str(error) == "absent":
            return None
        raise
    try:
        repair_state_dir(dirfd)
        raw = read_bounded(dirfd, STATE_NAME, MAX_STATE)
    finally:
        os.close(dirfd)
    if raw is None:
        return None
    try:
        doc = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        raise ScanError("saved scan was rejected")
    return validate_document(doc)


def store_state(home, doc):
    payload = json.dumps(validate_document(doc), separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(payload) > MAX_STATE:
        raise ScanError("saved scan was rejected")
    dirfd = open_dir_chain(home, PLUGIN_PARTS, lock_leaf=True)
    try:
        repair_state_dir(dirfd)
        write_atomic(dirfd, STATE_NAME, payload)
    finally:
        os.close(dirfd)


def csv_cell(value):
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return '"' + text.replace('"', '""') + '"'


def render_export(hosts, stamp):
    if not isinstance(stamp, str) or not _STAMP.fullmatch(stamp):
        raise ScanError("invalid export name")
    if not isinstance(hosts, list) or len(hosts) > MAX_HOSTS:
        raise ScanError("export is too large")
    header = ["ip", "alive", "latency_ms", "mac", "vendor", "hostname", "hostname_source", "open_ports"]
    csv_lines = [",".join(header)]
    text_lines = ["Mellow IP Scan", " ".join(header)]
    for row in hosts:
        validate_host(row)
        ports = " ".join(str(port) for port in row["ports"])
        values = [
            row["ip"],
            "yes" if row["alive"] else "no",
            "" if row["ms"] is None else str(row["ms"]),
            row["mac"],
            row["vendor"],
            row["hostname"],
            row["hostnameSource"],
            ports,
        ]
        csv_lines.append(",".join(csv_cell(value) for value in values))
        text_lines.append("\t".join(values))
    csv_blob = ("\n".join(csv_lines) + "\n").encode("utf-8")
    text_blob = ("\n".join(text_lines) + "\n").encode("utf-8")
    if len(csv_blob) + len(text_blob) > MAX_EXPORT:
        raise ScanError("export is too large")
    return "mellow-ip-scan-%s.csv" % stamp, csv_blob, "mellow-ip-scan-%s.txt" % stamp, text_blob


def export_files(home, hosts, stamp):
    csv_name, csv_blob, text_name, text_blob = render_export(hosts, stamp)
    dirfd = open_dir_chain(home, ("Downloads",), lock_leaf=False)
    try:
        write_atomic(dirfd, csv_name, csv_blob)
        write_atomic(dirfd, text_name, text_blob)
    finally:
        os.close(dirfd)
    return csv_name, text_name


def copy_text(text):
    if not isinstance(text, str):
        raise ScanError("nothing to copy")
    blob = text.encode("utf-8")
    if not blob or len(blob) > COPY_CAP:
        raise ScanError("nothing to copy")
    if not os.path.isfile(WL_COPY_BIN) or os.path.islink(WL_COPY_BIN):
        raise ScanError("copy needs wl-copy")
    proc = subprocess.Popen(
        [WL_COPY_BIN, "--"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env={
            "PATH": "/usr/bin",
            "LC_ALL": "C",
            "WAYLAND_DISPLAY": SESSION["WAYLAND_DISPLAY"],
            "XDG_RUNTIME_DIR": SESSION["XDG_RUNTIME_DIR"],
        },
    )
    err = bytearray()
    try:
        proc.stdin.write(blob)
        proc.stdin.close()
        deadline = time.monotonic() + 2
        while proc.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([proc.stderr], [], [], 0.2)
            if ready:
                chunk = os.read(proc.stderr.fileno(), 1024)
                if chunk:
                    err.extend(chunk)
                    if len(err) > 1024:
                        break
        if proc.poll() is None:
            _kill_group(proc.pid, signal.SIGKILL)
            proc.wait(timeout=1)
            raise ScanError("copy failed")
        proc.wait(timeout=1)
    finally:
        try:
            proc.stderr.close()
        except OSError:
            pass
    if proc.returncode != 0:
        raise ScanError(sanitize_text(err.decode("utf-8", "replace"), 80) or "copy failed")


def send_wol(mac, range_text):
    packet = magic_packet(mac)
    target = broadcast_of(range_text)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, (target, 9))
    finally:
        sock.close()
    return target


def read_request(limit=MAX_REQUEST):
    blob = b""
    fd = sys.stdin.fileno()
    deadline = time.monotonic() + 5
    while b"\n" not in blob and len(blob) <= limit:
        remain = deadline - time.monotonic()
        if remain <= 0:
            raise ScanError("request was not received")
        ready, _, _ = select.select([fd], [], [], min(remain, 0.2))
        if not ready:
            continue
        chunk = os.read(fd, min(4096, limit + 1 - len(blob)))
        if not chunk:
            break
        blob += chunk
    if len(blob) > limit or b"\n" not in blob:
        raise ScanError("request is too large")
    line, _rest = blob.split(b"\n", 1)
    try:
        doc = json.loads(line.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        raise ScanError("request is not JSON")
    if not isinstance(doc, dict):
        raise ScanError("request is not JSON")
    return doc


_VIRTUAL_IFACE = re.compile(
    r"^(lo|docker|br-|veth|virbr|tailscale|tun|tap|wg|zt|podman|cni|flannel|dummy|nm-shared|sit|ip6tnl|vnet)"
)


def _virtual_iface(name):
    return not isinstance(name, str) or bool(_VIRTUAL_IFACE.match(name))


def _range_score(ifname, local, prefix, device, source):
    score = 40 - abs(prefix - 24)
    if device and ifname == device:
        score += 1000
    if source and local == source:
        score += 100
    addr = ipaddress.IPv4Address(local)
    if addr.is_private:
        score += 200
    return score


def detect_range(ip_bin=IP_BIN):
    code, out, _err = run_capped([ip_bin, "-4", "-j", "route"], 2, 65536)
    if code != 0:
        raise ScanError("could not read routes")
    try:
        routes = json.loads(_decode(out, 65536))
    except json.JSONDecodeError:
        raise ScanError("could not read routes")
    device = ""
    source = ""
    if isinstance(routes, list):
        for route in routes:
            if isinstance(route, dict) and route.get("dst") == "default":
                device = route.get("dev") if isinstance(route.get("dev"), str) else ""
                source = route.get("prefsrc") if isinstance(route.get("prefsrc"), str) else ""
                break
    code, out, _err = run_capped([ip_bin, "-4", "-j", "addr"], 2, 65536)
    if code != 0:
        raise ScanError("could not read addresses")
    try:
        addresses = json.loads(_decode(out, 65536))
    except json.JSONDecodeError:
        raise ScanError("could not read addresses")
    best = None
    best_score = None
    if isinstance(addresses, list):
        for link in addresses:
            if not isinstance(link, dict):
                continue
            ifname = link.get("ifname")
            if _virtual_iface(ifname):
                continue
            for info in link.get("addr_info") or []:
                if not isinstance(info, dict) or info.get("family") != "inet":
                    continue
                local = info.get("local")
                prefix = info.get("prefixlen")
                # /31 and /32 are point-to-point. /21 and wider do not fit.
                if not isinstance(local, str) or not _finite_int(prefix, 22, 30):
                    continue
                try:
                    parse_ip(local)
                    network = ipaddress.IPv4Network("%s/%s" % (local, prefix), strict=False)
                except (ScanError, ValueError):
                    continue
                if network.num_addresses > MAX_HOSTS:
                    continue
                score = _range_score(ifname, local, prefix, device, source)
                if best is None or score > best_score:
                    best = str(network)
                    best_score = score
    if not best:
        raise ScanError("no scannable subnet")
    expand_range(best)
    return best


# The panel hotkey is one fixed block. The chord and the command are
# constants, so a click cannot splice a different key or program in.
HOTKEY_BEGIN = "-- mellow-ip-scan: begin"
HOTKEY_BODY = 'o.bind("SUPER + ALT + N", "Mellow IP Scan", { panel = "io.github.07dcolem.mellow-ip-scan" })'
HOTKEY_END = "-- mellow-ip-scan: end"
HOTKEY_BLOCK = HOTKEY_BEGIN + "\n" + HOTKEY_BODY + "\n" + HOTKEY_END + "\n"
BINDINGS_DIR = (".config", "hypr")
BINDINGS_NAME = "bindings.lua"
MAX_BINDINGS = 256 * 1024
HYPRCTL = "/usr/bin/hyprctl"
# Hyprland: SUPER is bit 6, ALT is bit 3.
PANEL_CHORD_MASK = (1 << 6) | (1 << 3)


def _chord_lines(text):
    count = 0
    for line in text.splitlines():
        folded = "".join(line.split()).upper()
        if "SUPER+ALT+N" in folded:
            count += 1
    return count


def classify_bindings(text):
    """Return free, ours, taken, or broken. broken refuses to write."""
    if not isinstance(text, str) or "\x00" in text:
        return "broken"
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError:
        return "broken"
    if size > MAX_BINDINGS:
        return "broken"
    lines = text.splitlines()
    begins = [index for index, line in enumerate(lines) if line == HOTKEY_BEGIN]
    ends = [index for index, line in enumerate(lines) if line == HOTKEY_END]
    if len(begins) != len(ends) or len(begins) > 1:
        return "broken"
    chords = _chord_lines(text)
    if len(begins) == 1:
        if ends[0] != begins[0] + 2 or lines[begins[0] + 1] != HOTKEY_BODY or chords != 1:
            return "broken"
        return "ours"
    if chords:
        return "taken"
    return "free"


def render_panel_hotkey_bytes(blob):
    """Append the fixed block to a free file. Other states are left untouched."""
    if not isinstance(blob, bytes) or len(blob) > MAX_BINDINGS or b"\x00" in blob:
        return "broken", None
    try:
        text = blob.decode("utf-8", "strict")
    except UnicodeError:
        return "broken", None
    state = classify_bindings(text)
    if state != "free":
        return state, None
    prefix = blob
    if prefix and not prefix.endswith(b"\n"):
        prefix += b"\n"
    rendered = prefix + HOTKEY_BLOCK.encode("ascii")
    if len(rendered) > MAX_BINDINGS:
        return "broken", None
    return "set", rendered


def splice_hotkey_block(blob):
    """Remove one exact hotkey block. None means the file must be left as it is."""
    if not isinstance(blob, bytes) or len(blob) > MAX_BINDINGS or b"\x00" in blob:
        return None
    try:
        text = blob.decode("utf-8", "strict")
    except UnicodeError:
        return None
    block = HOTKEY_BLOCK
    if text.count(block) != 1:
        return None
    index = text.find(block)
    if index > 0 and text[index - 1] != "\n":
        return None
    updated = text[:index] + text[index + len(block):]
    try:
        rendered = updated.encode("utf-8")
    except UnicodeError:
        return None
    if len(rendered) > MAX_BINDINGS:
        return None
    return rendered


def replace_if_current(dirfd, name, expected, data, limit):
    """Write data only while the file is still expected. A newer file is kept."""
    loaded = read_shared(dirfd, name, limit)
    if loaded is None or loaded[0] != expected:
        return False
    write_shared(dirfd, name, data, loaded[1], limit)
    return True


def binds_include_panel_chord(blob):
    try:
        rows = json.loads(blob)
    except (json.JSONDecodeError, UnicodeError):
        raise ScanError("could not read keybindings")
    if not isinstance(rows, list):
        raise ScanError("could not read keybindings")
    for row in rows:
        if not isinstance(row, dict) or row.get("mouse") is True:
            continue
        key = row.get("key")
        mask = row.get("modmask")
        if not isinstance(key, str) or key.upper() != "N":
            continue
        if isinstance(mask, bool) or not isinstance(mask, int) or mask != PANEL_CHORD_MASK:
            continue
        submap = row.get("submap")
        if submap in ("", None):
            return True
    return False


def combine_hotkey(file_state, live_taken):
    if file_state != "free":
        return file_state
    if live_taken:
        return "taken"
    return "free"


def read_shared(dirfd, name, limit):
    """Read one regular file the user owns. Group or other write is refused."""
    if not _ok_component(name):
        raise ScanError("refusing bindings")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dirfd)
    except FileNotFoundError:
        return None
    except OSError:
        raise ScanError("refusing bindings")
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > limit):
            raise ScanError("refusing bindings")
        os.set_blocking(fd, True)
        blob = b""
        while len(blob) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(blob)))
            if not chunk:
                break
            blob += chunk
        if len(blob) > limit:
            raise ScanError("refusing bindings")
        return blob, info.st_mode & 0o777
    finally:
        os.close(fd)


def write_shared(dirfd, name, data, mode, limit):
    """Replace one file in place, keeping its mode, without following a symlink."""
    if not _ok_component(name) or not isinstance(data, bytes) or len(data) > limit:
        raise ScanError("refusing bindings")
    mode &= 0o777
    if mode & 0o022:
        raise ScanError("refusing bindings")
    import secrets
    tmp = ".mellow-hotkey.%s.tmp" % secrets.token_hex(8)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dirfd)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ScanError("short write")
            view = view[written:]
        os.fsync(fd)
        os.rename(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        os.fsync(dirfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dirfd)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def _hypr_env():
    runtime = SESSION["XDG_RUNTIME_DIR"]
    signature = SESSION["HYPRLAND_INSTANCE_SIGNATURE"]
    if not runtime or not signature:
        raise ScanError("could not read keybindings")
    env = {"XDG_RUNTIME_DIR": runtime, "HYPRLAND_INSTANCE_SIGNATURE": signature}
    if SESSION["WAYLAND_DISPLAY"]:
        env["WAYLAND_DISPLAY"] = SESSION["WAYLAND_DISPLAY"]
    return env


def _hyprctl(args, timeout, limit):
    code, out, _err = run_capped([HYPRCTL, *args], timeout, limit, 8192, _hypr_env())
    if code != 0:
        raise ScanError("could not read keybindings")
    return out


def live_panel_chord():
    return binds_include_panel_chord(_hyprctl(["binds", "-j"], 5, 1024 * 1024))


def _append_fresh_hotkey(dirfd):
    """Append the block to the file from a new read. A save in between is kept."""
    for _attempt in (1, 2):
        loaded = read_shared(dirfd, BINDINGS_NAME, MAX_BINDINGS)
        if loaded is None:
            return "broken", False
        blob, _mode = loaded
        rendered_state, rendered = render_panel_hotkey_bytes(blob)
        if rendered_state == "broken":
            return "broken", False
        if rendered_state != "set" or rendered is None:
            return rendered_state, False
        if replace_if_current(dirfd, BINDINGS_NAME, blob, rendered, MAX_BINDINGS):
            return "ours", True
    return "free", False


def _drop_fresh_hotkey(dirfd):
    """Remove one exact block from the current file. Never write an older copy back."""
    for _attempt in (1, 2):
        loaded = read_shared(dirfd, BINDINGS_NAME, MAX_BINDINGS)
        if loaded is None:
            return False
        blob, _mode = loaded
        stripped = splice_hotkey_block(blob)
        if stripped is None or stripped == blob:
            return False
        if replace_if_current(dirfd, BINDINGS_NAME, blob, stripped, MAX_BINDINGS):
            return True
    return False


def panel_hotkey(home, write):
    """Read the user bindings. write=True appends the block and reloads Hyprland."""
    dirfd = open_dir_chain(home, BINDINGS_DIR, lock_leaf=False, create=False)
    try:
        loaded = read_shared(dirfd, BINDINGS_NAME, MAX_BINDINGS)
        if loaded is None:
            return "broken", False
        blob, _mode = loaded
        rendered_state, _rendered = render_panel_hotkey_bytes(blob)
        if rendered_state == "broken":
            return "broken", False
        file_state = "free" if rendered_state == "set" else rendered_state
        try:
            live = live_panel_chord()
        except ScanError:
            if write:
                return "broken", False
            raise
        state = combine_hotkey(file_state, live)
        if not write or state != "free":
            return state, False
        # binds and configerrors wait on Hyprland. The file read above is stale
        # after that wait, so the write and any undo both use a later read.
        before = _hyprctl(["configerrors"], 5, 65536)
        state, wrote = _append_fresh_hotkey(dirfd)
        if not wrote:
            return state, False
        try:
            _hyprctl(["reload"], 8, 65536)
            after = _hyprctl(["configerrors"], 5, 65536)
            if before.strip() != after.strip():
                raise ScanError("hyprland reported new config errors")
        except ScanError:
            if _drop_fresh_hotkey(dirfd):
                try:
                    _hyprctl(["reload"], 8, 65536)
                except ScanError:
                    pass
            raise
        return "ours", True
    finally:
        os.close(dirfd)


def main(argv):
    capture_session()
    scrub_environ()
    if len(argv) != 2 or argv[1] not in ("detect", "scan", "wol", "read-state", "write-state", "export", "copy", "tools", "hotkey-status", "hotkey-set"):
        return 2
    verb = argv[1]
    home = passwd_home()
    try:
        if verb == "detect":
            emit({"t": "detect", "range": detect_range()})
        elif verb == "read-state":
            doc = load_state(home)
            if doc is None:
                emit({"t": "state", "scan": None})
            else:
                emit({
                    "t": "meta", "scannedAt": doc["scannedAt"], "range": doc["range"],
                    "total": doc["total"], "done": doc["done"], "alive": doc["alive"],
                    "partial": doc["partial"],
                })
                for row in doc["hosts"]:
                    emit({"t": "host", **row})
                emit({"t": "end"})
        elif verb == "write-state":
            store_state(home, validate_document(read_request()))
            emit({"t": "wrote"})
        elif verb == "scan":
            req = read_request()
            if set(req) - {"range", "ports", "portChecks"}:
                raise ScanError("request is not JSON")
            stop = threading.Event()

            def _stop(_signum, _frame):
                stop.set()

            signal.signal(signal.SIGTERM, _stop)
            signal.signal(signal.SIGINT, _stop)
            doc = scan_hosts(
                req.get("range", ""),
                req.get("ports", ""),
                req.get("portChecks", False) is True,
                stop=stop,
            )
            try:
                store_state(home, doc)
            except ScanError as error:
                emit({"t": "error", "error": sanitize_text(str(error), 160)})
        elif verb == "wol":
            req = read_request()
            target = send_wol(req.get("mac", ""), req.get("range", ""))
            emit({"t": "wol", "broadcast": target})
        elif verb == "export":
            req = read_request(MAX_EXPORT)
            csv_name, text_name = export_files(home, req.get("hosts", []), req.get("stamp", ""))
            emit({"t": "export", "csv": csv_name, "txt": text_name})
        elif verb == "copy":
            req = read_request()
            copy_text(req.get("text", ""))
            emit({"t": "copied"})
        elif verb == "tools":
            emit({"t": "tools", "missing": ",".join(tool_gaps())})
        elif verb == "hotkey-status":
            state, _wrote = panel_hotkey(home, False)
            emit({"t": "hotkey", "state": state})
        elif verb == "hotkey-set":
            state, wrote = panel_hotkey(home, True)
            emit({"t": "hotkey", "state": state, "wrote": wrote is True})
    except ScanError as error:
        return fail(str(error))
    except OSError:
        return fail("scan failed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
