"""
Network interface discovery and selection using Scapy + socket fallbacks.
"""

import threading
import socket
import platform
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from app.logging.logger import log_capture, log_error, log_application


@dataclass
class NetworkInterface:
    name: str
    description: str = ""
    friendly_name: str = ""
    mac: str = ""
    ipv4: str = ""
    ipv6: str = ""
    is_loopback: bool = False
    is_up: bool = True
    raw: Any = None

    @property
    def label(self) -> str:
        if self.friendly_name:
            base = self.friendly_name
        elif self.description:
            base = self.description
        else:
            base = self.name
        extra_bits = []
        if self.ipv4:
            extra_bits.append(self.ipv4)
        if self.mac:
            extra_bits.append(self.mac)
        if extra_bits:
            return f"{base}  [{', '.join(extra_bits)}]"
        return base


class InterfaceManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._interfaces: List[NetworkInterface] = []
        self._selected: Optional[NetworkInterface] = None
        self.refresh()

    def _scapy_get_interfaces(self) -> List[NetworkInterface]:
        interfaces: List[NetworkInterface] = []
        try:
            from scapy.arch import get_if_list, get_if_hwaddr, get_if_addr
            from scapy.config import conf as scapy_conf
        except Exception as e:
            log_error("Scapy not available for interface enumeration.", e)
            return interfaces
        try:
            iface_data = getattr(scapy_conf, "ifaces", None)
            if iface_data is not None and hasattr(iface_data, "dev_from_index"):
                try:
                    vals = list(iface_data.values())
                except TypeError:
                    vals = []
                for dev in vals:
                    name = ""
                    desc = ""
                    friendly = ""
                    mac = ""
                    ipv4 = ""
                    ipv6 = ""
                    try:
                        if isinstance(dev, dict):
                            name = str(dev.get("name") or dev.get("dev") or dev.get("iface") or "")
                            desc = str(dev.get("description") or dev.get("desc") or "")
                            friendly = str(dev.get("friendly_name") or dev.get("win_description") or "")
                            mac = str(dev.get("mac") or dev.get("hwaddr") or "")
                            ips = dev.get("ips") or dev.get("ip") or {}
                            if isinstance(ips, list):
                                for ip in ips:
                                    if ":" in str(ip):
                                        ipv6 = str(ip)
                                    else:
                                        ipv4 = str(ip)
                            elif isinstance(ips, dict):
                                for k, v in ips.items():
                                    kstr = str(k)
                                    vstr = str(v)
                                    if ":" in vstr or "6" in kstr:
                                        ipv6 = vstr
                                    else:
                                        ipv4 = vstr
                        else:
                            name = str(getattr(dev, "name", "") or getattr(dev, "dev", "") or str(dev))
                            desc = str(getattr(dev, "description", "") or "")
                            friendly = str(getattr(dev, "friendly_name", "") or "")
                            mac = str(getattr(dev, "mac", "") or getattr(dev, "hwaddr", "") or "")
                            ips = getattr(dev, "ips", None) or getattr(dev, "ip", None)
                            if isinstance(ips, dict):
                                for k, v in ips.items():
                                    if isinstance(v, list):
                                        for vv in v:
                                            s = str(vv)
                                            if ":" in s:
                                                ipv6 = s
                                            else:
                                                ipv4 = s
                                    else:
                                        s = str(v)
                                        if ":" in s:
                                            ipv6 = s
                                        else:
                                            ipv4 = s
                    except Exception as ie:
                        log_error(f"Error parsing interface {dev!r}", ie)
                    if not name:
                        continue
                    is_loopback = ("loopback" in (desc + " " + name + " " + friendly).lower()) or (ipv4.startswith("127.") or name.lower() in ("lo", "loopback", "localhost"))
                    interfaces.append(NetworkInterface(
                        name=name, description=desc, friendly_name=friendly,
                        mac=mac, ipv4=ipv4, ipv6=ipv6, is_loopback=is_loopback, raw=dev,
                    ))
        except Exception as e:
            log_error("Failed to enumerate interfaces via scapy ifaces dict.", e)

        try:
            found_names = {i.name for i in interfaces}
            for name in get_if_list():
                if name in found_names:
                    continue
                try:
                    mac = get_if_hwaddr(name) if get_if_hwaddr else ""
                except Exception:
                    mac = ""
                try:
                    ipv4 = get_if_addr(name) if get_if_addr else ""
                except Exception:
                    ipv4 = ""
                is_loopback = ipv4.startswith("127.") or name.lower() in ("lo", "loopback")
                interfaces.append(NetworkInterface(
                    name=name, description=name, friendly_name="",
                    mac=mac, ipv4=ipv4, ipv6="", is_loopback=is_loopback,
                ))
        except Exception as e:
            log_error("Fallback scapy interface list enumeration failed.", e)
        return interfaces

    def _socket_get_interfaces(self) -> List[NetworkInterface]:
        interfaces: List[NetworkInterface] = []
        host = ""
        try:
            host = socket.gethostname()
            infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC)
            ips = set()
            for info in infos:
                try:
                    ip = info[4][0]
                    if ip:
                        ips.add(ip)
                except (IndexError, TypeError):
                    pass
            if ips:
                ipv4 = ""
                ipv6 = ""
                for ip in sorted(ips):
                    if ":" in ip:
                        ipv6 = ip
                    else:
                        ipv4 = ip
                interfaces.append(NetworkInterface(
                    name="default", description=f"Default host interface ({host})",
                    friendly_name=host, mac="", ipv4=ipv4, ipv6=ipv6, is_loopback=False,
                ))
        except Exception as e:
            log_error("Socket-based interface enumeration failed.", e)
        interfaces.append(NetworkInterface(
            name="Loopback", description="Software loopback interface",
            friendly_name="Loopback", mac="", ipv4="127.0.0.1", ipv6="::1", is_loopback=True,
        ))
        return interfaces

    def refresh(self) -> List[NetworkInterface]:
        with self._lock:
            scapy_interfaces = self._scapy_get_interfaces()
            if scapy_interfaces:
                self._interfaces = scapy_interfaces
            else:
                self._interfaces = self._socket_get_interfaces()
            self._interfaces = sorted(
                self._interfaces,
                key=lambda i: (i.is_loopback, not (i.ipv4 or i.ipv6), i.label.lower()),
            )
            log_application(f"Discovered {len(self._interfaces)} network interfaces.", "INFO")
            return list(self._interfaces)

    def list_interfaces(self) -> List[NetworkInterface]:
        with self._lock:
            return list(self._interfaces)

    def select_interface(self, name: str) -> Optional[NetworkInterface]:
        with self._lock:
            for iface in self._interfaces:
                if iface.name == name or iface.label == name or iface.friendly_name == name:
                    self._selected = iface
                    log_capture(f"Interface selected: {iface.label}", "INFO")
                    return iface
            self._selected = None
            log_capture(f"Could not select interface '{name}': not found.", "WARNING")
            return None

    def get_selected(self) -> Optional[NetworkInterface]:
        with self._lock:
            return self._selected

    def is_loopback_available(self) -> bool:
        with self._lock:
            return any(i.is_loopback for i in self._interfaces)
