import re
import shlex
import subprocess

from loguru import logger

from settings import settings

# fixed, read-only: DHCP leases, user-set nicknames, ARP table (devices with static IPs)
COMMAND = "cat /var/lib/misc/dnsmasq.leases; echo @@; nvram get custom_clientlist; echo @@; cat /proc/net/arp"


def _label(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:24]


def parse_router_output(output: str) -> dict[str, dict]:
    """IP -> {label}: the router nickname if set, else the DHCP hostname; devices with neither stay unnamed"""
    leases, nicknames_raw, arp = output.split("@@\n")
    nicknames = {}
    for entry in nicknames_raw.strip().split("<"):
        fields = entry.split(">")
        if len(fields) >= 2 and fields[0]:
            nicknames[fields[1].upper()] = fields[0]
    ip_mac, hostnames = {}, {}
    for line in leases.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            ip_mac[parts[2]] = parts[1].upper()
            if parts[3] != "*":
                hostnames[parts[2]] = parts[3]
    for line in arp.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
            ip_mac.setdefault(parts[0], parts[3].upper())
    devices = {}
    for ip, mac in ip_mac.items():
        name = nicknames.get(mac) or hostnames.get(ip)
        if name:
            devices[ip] = {"label": _label(name)}
    return devices


def get_router_devices() -> dict[str, dict]:
    """Read the router's client data over SSH, through the jump host's own router login when one is set; any failure raises, nothing is retried"""
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={settings.router_timeout}"]
    on_router = [*ssh, settings.router_ssh_host, COMMAND]
    command = [*ssh, settings.router_ssh_jump, shlex.join(on_router)] if settings.router_ssh_jump else on_router
    result = subprocess.run(command, capture_output=True, text=True, timeout=settings.router_timeout * 3, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Router SSH failed (exit {result.returncode}): {result.stderr.strip()[:200]}")
    devices = parse_router_output(result.stdout)
    logger.info(f"Router: {len(devices)} devices named")
    return devices
