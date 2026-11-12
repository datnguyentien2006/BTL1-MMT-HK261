"""Discover local interfaces and generate invitation QR codes without Internet."""
from functools import lru_cache
import ipaddress
import socket

import psutil
import qrcode
from qrcode.image.svg import SvgPathFillImage


def lan_addresses(bind_ip, destination_ip=None):
    """Return active IPv4 interfaces accepted by this listener, physical ones first.

    Interface names only help ranking; the actual request destination takes
    precedence. No public DNS lookup, external probe or default gateway is needed.
    """
    if ipaddress.IPv4Address(bind_ip).is_loopback:
        return []
    found = {}
    try:
        stats = psutil.net_if_stats()
        for name, addresses in psutil.net_if_addrs().items():
            if name not in stats or not stats[name].isup:
                continue
            for address in addresses:
                if address.family != socket.AF_INET:
                    continue
                ip = ipaddress.IPv4Address(address.address)
                if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
                    continue
                if bind_ip != '0.0.0.0' and str(ip) != bind_ip:
                    continue
                found.setdefault(str(ip), name)
    except (OSError, psutil.Error):
        pass
    # Explicit bind or a successful LAN request is useful even if enumeration fails.
    for address in (bind_ip, destination_ip):
        if address is None:
            continue
        ip = ipaddress.IPv4Address(address)
        if not (ip.is_unspecified or ip.is_loopback or ip.is_multicast):
            if bind_ip == '0.0.0.0' or address == bind_ip:
                found.setdefault(address, 'LAN')

    def priority(item):
        ip, name = item
        virtual = any(part in name.lower() for part in (
            'vmware', 'vmnet', 'vethernet', 'virtual', 'vbox', 'vpn', 'tailscale',
            'zerotier', 'docker', 'bridge', 'tun', 'tap', 'wsl'))
        return (ip != destination_ip, virtual, name.lower(), ip)

    return [{'ip': ip, 'interface': name} for ip, name in sorted(found.items(), key=priority)]


def invitation_info(bind_ip, port, destination_ip=None):
    entries = [{**entry, 'url': f"http://{entry['ip']}:{port}",
                'qr_url': f"/api/invite-qr.svg?ip={entry['ip']}"}
               for entry in lan_addresses(bind_ip, destination_ip)]
    return {'local_only': ipaddress.IPv4Address(bind_ip).is_loopback, 'addresses': entries}


@lru_cache(maxsize=32)
def invitation_qr(url):
    # Fixed server-generated URL only; no session tokens or user content in the QR.
    return qrcode.make(url, image_factory=SvgPathFillImage, border=4).to_string()
