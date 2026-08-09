# -*- coding: utf-8 -*-
"""LAN scanner for wifi-zero (works WITHOUT root on Android/Termux).

Strategy (no raw sockets available on stock Android):
  1. Enumerate our own interface from `ip -br addr`.
  2. Read the kernel neighbour/ARP table (`ip neigh show dev <iface>`), which
     is the ground truth of who is physically on the LAN (no privileges needed).
  3. Warm the neighbour table with a parallel TCP connect to 53/80/443 (this
     forces ARP resolution and populates `ip neigh`).
  4. Deep service scan (top ports) on alive hosts to fill the "ports" table.
  5. Resolve MAC vendor via the OUI DB shipped with Nmap.
"""
import os
import re
import subprocess
import sys
import socket
import concurrent.futures as cf

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))
import db  # noqa: E402

PREFIX = "/data/data/com.termux/files/usr"

WARM_PORTS = [53, 80, 443]
SCAN_PORTS = [22, 53, 80, 123, 443, 445, 554, 1900, 5060, 5353, 8000, 8080, 8443, 8888, 9090, 49152]

OUI_FILE = os.path.join(PREFIX, "share", "nmap", "nmap-mac-prefixes")

IP_CMD = "/system/bin/ip"


def _ip(args):
    """Run the Android `ip` binary (not on PATH in Termux)."""
    return subprocess.run([IP_CMD] + args, capture_output=True, text=True).stdout


# ---------------------------------------------------------------- interfaces
def list_interfaces():
    """Return dict iface -> {'ip','prefix'} using `ip -br addr`."""
    out = _ip(["-br", "addr"])
    ifaces = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0] == "lo":
            continue
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", parts[2])
        if m:
            ifaces[parts[0]] = {"ip": m.group(1), "prefix": int(m.group(2))}
    return ifaces


def resolve_iface(ifname="wlan0"):
    ifs = list_interfaces()
    if ifname in ifs:
        return ifs[ifname]
    for n, d in ifs.items():
        if str(d["ip"]).startswith(("192.168.", "10.")):
            return d
    if ifs:
        return next(iter(ifs.values()))
    return None


def iface_to_range(info):
    """Return a /24 style base (e.g. 192.168.1) regardless of prefix."""
    from ipaddress import ip_network
    nw = ip_network(f"{info['ip']}/{info['prefix']}", strict=False)
    return str(nw.network_address)


def build_hosts(cidr="192.168.1.0/24"):
    from ipaddress import ip_network
    try:
        net = ip_network(cidr, strict=False)
        if net.num_addresses > 4096:  # stay sane on a phone
            net = ip_network("192.168.1.0/24", strict=False)
    except Exception:
        net = ip_network("192.168.1.0/24", strict=False)
    hosts = [str(h) for h in net.hosts()]
    return hosts


# ------------------------------------------------------------ kernel neigh
def read_neighbors(iface=None):
    """Parse `ip neigh show`; ground truth without root."""
    cmd = ["neigh", "show"] + (["dev", iface] if iface else [])
    out = _ip(cmd)
    alive = {}
    for line in out.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+.*?lladdr\s+(\S+)", line)
        if not m:
            continue
        ip, mac = m.groups()
        state = 0
        if "FAILED" not in line and "INCOMPLETE" not in line:
            state = 1
        alive[ip] = {"mac": mac.lower(), "state": state}
    return alive


# ---------------------------------------------------------------- tcp probe
def _connect(ip, port, timeout=0.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def tcp_probe(ip, ports, timeout=0.5):
    return [p for p in ports if _connect(ip, p, timeout)]


def tcp_sweep(hosts, ports, workers=96, timeout=0.4):
    results = {}

    def work(h):
        return h, tcp_probe(h, ports, timeout)

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for ip, openp in ex.map(work, hosts):
            if openp:
                results[ip] = openp
    return results


# ------------------------------------------------------------------- vendor
_oui = None


def _load_oui():
    global _oui
    if _oui is not None:
        return _oui
    _oui = {}
    if os.path.exists(OUI_FILE):
        with open(OUI_FILE, "r", errors="ignore") as f:
            for line in f:
                m = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line.strip())
                if m:
                    _oui[m.group(1).upper()] = m.group(2)
    return _oui


def mac_vendor(mac):
    if not mac:
        return None
    key = mac.replace(":", "").upper()
    oui = _load_oui()
    if not oui:
        return "?"
    for cut in (6, 4, 2):
        if key[:cut] in oui:
            return oui[key[:cut]]
    return None


# ------------------------------------------------------------------ F3: nmap -sV (service/version) ---------------------------------
def nmap_service_probe(ip, ports, ifname="wlan0", nmap_bin=None):
    """Invoca `nmap -sV` sobre un host; devuelve dict port→{service,product,version}.

    Usa scan TCP connect (funciona sin root). Se limita a puertos concretos para
    no arrastrar nmap por todo el rango en el móvil.
    """
    nmap_bin = nmap_bin or "/data/data/com.termux/files/usr/bin/nmap"
    if not ports:
        return {}
    targets = ",".join(str(p) for p in ports)
    out = subprocess.run(
        [nmap_bin, "-sV", "-sT", "-Pn", "-n", "-e", ifname,
         "-p", targets, "-oN", "-", ip],
        capture_output=True, text=True, timeout=120,
    )
    return _parse_nmap_sv(out.stdout)


def _parse_nmap_sv(text):
    """Parse simple de `nmap -sV` -> {port: {service,product,version}}."""
    res = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)(.*)$", line.strip())
        if m:
            port, svc, tail = int(m.group(1)), m.group(2), m.group(3)
            res[port] = {"service": svc, "product": None, "version": None}
            cur = res[port]
        elif cur and line.strip():
            # "Product Foo 1.2.3" styles
            p = re.match(r"^\s*Product:\s*(.+)$", line)
            v = re.match(r"^\s*Version:\s*(.+)$", line)
            if p:
                cur["product"] = p.group(1).strip()
            elif v:
                cur["version"] = v.group(1).strip()
    return res


# ------------------------------------------------------------------ F3 NSE broadcast (sin root)
def nse_broadcast_scan(ifname="wlan0", timeout=20):
    """Corre scripts broadcast de nmap que SÍ funcionan sin privilegios
    (detección de dispositivos por DNS-SD / SSDP de la red). Devuelve texto crudo."""
    nmap_bin = "/data/data/com.termux/files/usr/bin/nmap"
    scripts = "broadcast-dns-service-discovery,broadcast-upnp-info"
    out = subprocess.run(
        [nmap_bin, "--script", scripts, "-e", ifname, "-n"],
        capture_output=True, text=True, timeout=timeout,
    )
    return out.stdout


def scan_once(ifname="wlan0", cfg=None):
    """Escaneo completo: neigh + TCP sweep + persistencia + nmap -sV."""
    con = db.connect()
    iface = resolve_iface(ifname)
    if not iface:
        print("[lan] no usable interface")
        return {}

    base = iface_to_range(iface)
    cidr = f"{base}/24"
    print(f"[lan] scanning {cidr} via {ifname} ({iface['ip']})")

    # 1) kernel neighbours (ground truth)
    neigh = read_neighbors(ifname)
    live = {ip for ip, n in neigh.items() if n["state"]}
    print(f"[lan] kernel neighbours: {len(live)}")

    # 2) TCP probe to warm the table + detect alive anything
    hosts = build_hosts(cidr)
    sweep = tcp_sweep(hosts, WARM_PORTS, timeout=0.4)
    for ip in sweep:
        live.add(ip)
    print(f"[lan] alive (neigh+tcp): {len(live)}")

    # 3) persist hosts
    macs = {ip: n.get("mac") for ip, n in neigh.items()}
    for ip in live:
        mac = macs.get(ip)
        db.upsert_host(con, ip, mac=mac, vendor=mac_vendor(mac) if mac else None, state=1)
    for ip in set(neigh) - live:
        db.upsert_host(con, ip, mac=neigh[ip].get("mac"),
                       vendor=mac_vendor(neigh[ip].get("mac")) if neigh[ip].get("mac") else None,
                       state=0)

    # 4) service scan on live hosts (TCP probe + nmap -sV si hay puertos)
    cfg_sv = True
    for ip in live:
        ports = tcp_probe(ip, SCAN_PORTS, timeout=0.5)
        if ports:
            for p in ports:
                db.upsert_port(con, ip, p)
            if cfg_sv:
                try:
                    sv = nmap_service_probe(ip, ports, ifname=ifname)
                    for p, meta in sv.items():
                        db.upsert_port(con, ip, p, service=meta.get("service"),
                                       product=meta.get("product"), version=meta.get("version"))
                except Exception as e:
                    print(f"[lan] nmap -sV {ip} err: {e}")

    db.log_run(con, "lan", host_count=len(live))
    print(f"[lan] done: {len(live)} alive hosts")
    return {"alive": len(live), "base": base}


if __name__ == "__main__":
    ifname = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
    scan_once(ifname)