#!/usr/bin/env python3
"""Downstream — passive-first OT/ICS asset discovery with BloodHound-style graphing.

Architecture (single-file, Deadfall pattern):
  - Model: asset/edge/finding store, MAC<->IP merge, OUI vendor enrichment
  - Passive dissectors: modbus, s7comm, enip, dnp3, opcua, bacnet, lldp,
    profinet dcp/rt, nbns, dhcp, arp
  - Zones/Purdue inference from scope config; role inference from protocol behavior
  - Findings engine: unmanaged devices, rogue masters, enterprise->control paths, writes
  - Gated active layer: arp_ping / tcp_probe / modbus_id / enip_list
    (allow|confirm|block per technique, dry-run default, --execute required,
     write-class probes NOT IMPLEMENTED by design)
  - Exports: graphviz dot (+svg/png), csv, markdown report, json state
  - Flask API + vendored-d3 single-file UI (air-gap friendly)

Usage:
  downstream.py ingest <pcap...> [--scope scope.json] [--db state.json]
  downstream.py live --iface <iface> [--scope ...] [--db ...]
  downstream.py active --scope scope.json [--plan-only|--execute [--yes]]
  downstream.py export --db state.json --format dot|svg|png|csv|md|json [-o out]
  downstream.py serve [--port 8756] [--db state.json]
"""
from __future__ import annotations

import csv
import io
import json
import os
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUI_PATH = ROOT / "data" / "oui.txt"

# --------------------------------------------------------------------------
# Vendor / OUI
# --------------------------------------------------------------------------

def load_oui(path: Path = OUI_PATH) -> dict:
    m = {}
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                if "(hex)" not in line:
                    continue
                head, _, org = line.partition("(hex)")
                prefix = head.strip()
                org = org.strip().rstrip(",")
                if len(prefix) == 8 and prefix[2] == "-":
                    m[prefix] = org
    except FileNotFoundError:
        pass
    return m

OUI = load_oui()

CONSUMER_VENDOR_PREFIXES = (
    "Apple", "Dell", "Lenovo", "ASUSTek", "Gigabyte", "Micro-Star", "MSI",
    "Samsung", "Xiaomi", "Espressif", "Google", "ecobee", "Nest Labs",
    "Shenzhen", "TP-Link", "Ring", "Amazon Technologies", "Roku", "Sonos",
)

def mac_vendor(mac: str) -> str:
    if not mac:
        return ""
    prefix = mac[:8].replace(":", "-").upper()
    return OUI.get(prefix, "")

def is_consumer_vendor(vendor: str) -> bool:
    return any(vendor.startswith(p) for p in CONSUMER_VENDOR_PREFIXES)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# --------------------------------------------------------------------------
# Scope
# --------------------------------------------------------------------------

DEFAULT_SCOPE = {
    "name": "unnamed engagement",
    "zones": {},           # {"L1": ["10.20.5.0/24"], ...}
    "excluded": [],
    "active": {"enabled": False, "techniques": {}},
}

class Scope:
    def __init__(self, data: dict | None = None):
        self.data = data or json.loads(json.dumps(DEFAULT_SCOPE))
        self.zone_nets = []
        for zone, cidrs in (self.data.get("zones") or {}).items():
            for c in cidrs or []:
                try:
                    self.zone_nets.append((ip_network(c, strict=False), zone))
                except ValueError:
                    pass
        self.excluded = [ip_network(c, strict=False) for c in self.data.get("excluded", [])]

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        with open(path) as f:
            return cls(json.load(f))

    def zone_of(self, ip: str) -> str:
        try:
            a = ip_address(ip)
        except ValueError:
            return "Unclassified"
        if any(a in n for n in self.excluded):
            return "Excluded"
        best, best_len = "Unclassified", -1
        for net, zone in self.zone_nets:
            if a in net and net.prefixlen > best_len:
                best, best_len = zone, net.prefixlen
        return best

    @staticmethod
    def purdue_of(zone: str) -> str:
        z = zone.lower()
        if z in ("l0", "l1", "level 0", "level 1"):
            return "L0/L1"
        if z in ("l2", "l3", "l2_l3", "l2/l3", "dmz", "level 2", "level 3"):
            return "L2/L3"
        if "enterprise" in z or z in ("l4", "l5", "level 4", "level 5", "it"):
            return "L4/L5"
        return "?"

    def in_scope(self, ip: str) -> bool:
        z = self.zone_of(ip)
        return z not in ("Excluded", "Unclassified") if self.zone_nets else True

    def active_decision(self, technique: str) -> str:
        cfg = self.data.get("active") or {}
        if not cfg.get("enabled"):
            return "block"
        return cfg.get("techniques", {}).get(technique, "confirm")

# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------

OT_PROTOCOLS = {"modbus", "s7comm", "enip", "dnp3", "opcua", "bacnet", "profinet_dcp", "profinet_rt"}
IOT_PROTOCOLS = {"mdns", "ssdp", "mqtt", "knxnet_ip"}
IOT_ROLES = {"iot_device", "mqtt_client", "knx_client", "mdns_querier"}
OT_ZONES = {"L1", "L2", "L3", "L2_L3"}

MODBUS_WRITE_FCS = {5, 6, 15, 16}

class Asset:
    def __init__(self, mac: str = "", ip: str = ""):
        self.mac = mac.upper() if mac else ""
        self.ips: set[str] = set()
        if ip:
            self.ips.add(ip)
        self.vendor = ""
        self.hostnames: set[str] = set()
        self.protocols: set[str] = set()
        self.roles: set[str] = set()
        self.attrs: dict = {}
        self.pkt_count = 0
        self.first_seen = ""
        self.last_seen = ""
        self.id_override = ""
        self._refresh_vendor()

    def _refresh_vendor(self):
        if not self.vendor and self.mac:
            self.vendor = mac_vendor(self.mac)

    def touch(self, ts: str = ""):
        self.pkt_count += 1
        if ts:
            if not self.first_seen:
                self.first_seen = ts
            self.last_seen = ts

    @property
    def id(self) -> str:
        if self.id_override:
            return self.id_override
        return self.mac or (f"ip:{sorted(self.ips)[0]}" if self.ips else "unknown")

    @property
    def label(self) -> str:
        if self.hostnames:
            return sorted(self.hostnames)[0]
        if self.ips:
            return sorted(self.ips)[0]
        return self.mac

    def zone(self, scope: Scope) -> str:
        for ip in sorted(self.ips):
            z = scope.zone_of(ip)
            if z != "Unclassified":
                return z
        # virtual child: inherit the gateway's zone
        if self.attrs.get("behind_gateway"):
            parent = getattr(self, "_parent_asset", None)
            if parent is not None:
                return parent.zone(scope)
        return "Unclassified"

    def is_unmanaged(self, scope: Scope) -> bool:
        z = self.zone(scope)
        if z not in ("L1", "L2", "L2_L3"):
            return False
        return is_consumer_vendor(self.vendor)

    def to_dict(self, scope: Scope) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "mac": self.mac,
            "ips": sorted(self.ips),
            "vendor": self.vendor,
            "hostnames": sorted(self.hostnames),
            "protocols": sorted(self.protocols),
            "roles": sorted(self.roles),
            "zone": self.zone(scope),
            "purdue": scope.purdue_of(self.zone(scope)),
            "pkt_count": self.pkt_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "unmanaged": self.is_unmanaged(scope),
            "attributes": self.attrs,
        }


class Edge:
    def __init__(self, src: str, dst: str, proto: str):
        self.src, self.dst, self.proto = src, dst, proto
        self.count = 0
        self.writes = 0
        self.exceptions = 0
        self.first_seen = self.last_seen = ""

    def touch(self, ts=""):
        self.count += 1
        if ts:
            if not self.first_seen:
                self.first_seen = ts
            self.last_seen = ts

    def key(self):
        return (self.src, self.dst, self.proto)

    def to_dict(self):
        return {"source": self.src, "target": self.dst, "proto": self.proto,
                "count": self.count, "writes": self.writes, "exceptions": self.exceptions}


def _same24(a: str, b: str) -> bool:
    return a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]


class Model:
    def __init__(self, scope: Scope | None = None):
        self.scope = scope or Scope()
        self.assets: dict[str, Asset] = {}
        self.edges: dict[tuple, Edge] = {}
        self.findings: list[dict] = []
        self.events: list[dict] = []
        self._ip_alias: dict[str, str] = {}   # ip -> asset id
        # gateway-layer crawl stats: (server_id, unit_or_link) -> activity
        self._mb_units: dict[tuple, dict] = {}
        self._dnp_links: dict[tuple, dict] = {}

    # -- logging -----------------------------------------------------------
    def log(self, kind: str, msg: str):
        self.events.append({"ts": now_iso(), "kind": kind, "msg": msg})
        self.events = self.events[-2000:]

    # -- asset management ----------------------------------------------------
    def _id_for_ip(self, ip: str) -> str:
        return self._ip_alias.get(ip, f"ip:{ip}")

    def resolve(self, ip: str = "", mac: str = "") -> Asset:
        """Get-or-create asset; merges ip-keyed and mac-keyed assets."""
        mac = mac.upper() if mac else ""
        if mac:
            existing = self.assets.get(mac)
            if existing is not None and ip:
                # Router guard: an infrastructure device (router/switch/gateway,
                # typically LLDP-learned) or a MAC that already owns an IP in a
                # DIFFERENT /24 is a last-hop router for routed traffic, not this
                # host. Keep the ip-keyed identity and note the route instead.
                infra = existing.roles & {"router", "switch", "gateway"}
                if infra or (existing.ips and not any(_same24(ip, o) for o in existing.ips)):
                    a = self.resolve(ip=ip)
                    a.attrs.setdefault("last_hop_router", mac)
                    return a
                existing.ips.add(ip)
                self._ip_alias[ip] = mac
                return existing
            a = self.assets.get(mac)
            if a is None and ip and ip in self._ip_alias:
                # promote existing ip asset to mac identity — but never onto
                # infrastructure roles learned via LLDP (router/switch/gateway
                # own their mgmt IP; another MAC claiming it is ARP spoofing
                # or a capture artifact, not a promotion)
                old_id = self._ip_alias[ip]
                old = self.assets.get(old_id)
                if old is not None and not (old.roles & {"router", "switch", "gateway"}):
                    old.mac = mac
                    old._refresh_vendor()
                    self.assets[mac] = old
                    if old_id != mac:
                        del self.assets[old_id]
                        # remap any edges that referenced the ip-keyed id
                        for e in self.edges.values():
                            if e.src == old_id:
                                e.src = mac
                            if e.dst == old_id:
                                e.dst = mac
                        # dict keys must follow the remapped ids
                        self.edges = {e.key(): e for e in self.edges.values()}
                        # remap per-gateway unit/link stats keyed by asset id
                        for stats in (self._mb_units, self._dnp_links):
                            for k in [k for k in stats if old_id in k]:
                                stats[(mac, k[1])] = stats.pop(k)
                    self._ip_alias[ip] = mac
                    return old
            if a is None:
                a = Asset(mac=mac, ip=ip)
                self.assets[mac] = a
            if ip:
                a.ips.add(ip)
                self._ip_alias[ip] = mac
            return a
        if ip:
            aid = self._id_for_ip(ip)
            a = self.assets.get(aid)
            if a is None:
                a = Asset(ip=ip)
                self.assets[aid] = a
                self._ip_alias[ip] = aid
            return a
        raise ValueError("need ip or mac")

    def bind(self, ip: str, mac: str):
        """Record an ip<->mac association (ARP, DHCP, PN-DCP, Ethernet+IP)."""
        a = self.resolve(ip=ip, mac=mac)
        return a

    def edge(self, src_id: str, dst_id: str, proto: str) -> Edge:
        k = (src_id, dst_id, proto)
        e = self.edges.get(k)
        if e is None:
            e = Edge(*k)
            self.edges[k] = e
        return e

    # -- ingestion -----------------------------------------------------------
    def ingest_pcap(self, path: str | Path) -> int:
        from scapy.all import PcapReader
        pkts = []
        with PcapReader(str(path)) as rdr:
            for pkt in rdr:
                pkts.append(pkt)
        n = self._ingest_batch(pkts)
        self.log("ingest", f"{path}: {n} packets processed")
        return n

    def ingest_packets(self, pkts) -> int:
        n = self._ingest_batch(list(pkts))
        self.log("ingest", f"live batch: {n} packets processed")
        return n

    def _ingest_batch(self, pkts) -> int:
        """Unified two-pass pipeline used by BOTH pcap and live ingestion:
        pass 1 (identity) is ordered so infrastructure is known before hosts:
          1a. LLDP frames -> router/switch roles + mgmt IPs
          1b. ARP + PROFINET -> MAC<->IP bindings, L2 identity
          1c. all other IP frames -> MAC<->IP binding evidence (+ DHCP)
        The router guard depends on 1a preceding 1c."""
        from scapy.all import ARP as ARP_cls, Ether as Ether_cls, IP as IP_cls, UDP as UDP_cls
        n = 0

        def ts_of(p):
            return datetime.fromtimestamp(float(p.time), tz=timezone.utc).isoformat(timespec="seconds") if p.time else ""

        for pkt in pkts:
            eth = pkt.getlayer(Ether_cls)
            if eth is not None and eth.type == 0x88CC:
                try:
                    self._on_lldp(eth.src, bytes(eth.payload), ts_of(pkt))
                except Exception:
                    continue
        for pkt in pkts:
            try:
                eth = pkt.getlayer(Ether_cls)
                if pkt.haslayer(ARP_cls):
                    self._on_arp(pkt[ARP_cls], ts_of(pkt))
                elif eth is not None and eth.type == 0x8892:
                    self._on_profinet(eth.src, eth.dst, bytes(eth.payload), ts_of(pkt))
            except Exception:
                continue
        for pkt in pkts:
            try:
                eth = pkt.getlayer(Ether_cls)
                if pkt.haslayer(IP_cls) and eth is not None and eth.src not in ("ff:ff:ff:ff:ff:ff", ""):
                    self.bind(pkt[IP_cls].src, eth.src)
                    if pkt.haslayer(UDP_cls) and (pkt[UDP_cls].dport in (67, 68) or pkt[UDP_cls].sport in (67, 68)):
                        self._on_dhcp(eth.src, bytes(pkt[UDP_cls].payload), ts_of(pkt))
            except Exception:
                continue
        # pass 2 (conversations): protocol dissectors build assets + edges
        for pkt in pkts:
            try:
                if self.parse_packet(pkt):
                    n += 1
            except Exception:
                continue
        self.recompute()
        return n

    def _harvest_identity(self, pkt) -> None:  # retained for live capture path
        from scapy.all import ARP, Ether, IP
        eth = pkt.getlayer(Ether)
        if eth is None:
            return
        payload = bytes(eth.payload)
        if eth.type == 0x88CC:
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat(timespec="seconds") if pkt.time else ""
            self._on_lldp(eth.src, payload, ts)
        elif pkt.haslayer(ARP):
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat(timespec="seconds") if pkt.time else ""
            self._on_arp(pkt[ARP], ts)
        elif pkt.haslayer(IP) and eth.src not in ("ff:ff:ff:ff:ff:ff", ""):
            # MAC<->IP binding evidence (subject to the router guard)
            self.bind(pkt[IP].src, eth.src)

    def parse_packet(self, pkt, ARP=None, Ether=None, IP=None, TCP=None, UDP=None) -> bool:
        if ARP is None:
            from scapy.all import ARP as _A, Ether as _E, IP as _I, TCP as _T, UDP as _U
            ARP, Ether, IP, TCP, UDP = _A, _E, _I, _T, _U
        eth = pkt.getlayer(Ether)
        ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat(timespec="seconds") if pkt.time else ""
        if eth is None:
            return False
        etype = eth.type
        src_mac, dst_mac = eth.src, eth.dst
        payload = bytes(eth.payload)

        if etype == 0x88CC:
            return self._on_lldp(src_mac, payload, ts)
        if etype == 0x8892:
            return self._on_profinet(src_mac, dst_mac, payload, ts)
        if pkt.haslayer(ARP):
            return self._on_arp(pkt[ARP], ts)

        if not pkt.haslayer(IP):
            return False
        ip = pkt[IP]
        sip, dip = ip.src, ip.dst

        # MAC<->IP binding evidence from any IP frame
        if src_mac and src_mac != "ff:ff:ff:ff:ff:ff":
            self.bind(sip, src_mac)

        # TTL-based hop inference: how many routers sit between the source and
        # the capture point. initial guess = smallest of {64,128,255} >= ttl.
        if ip.ttl:
            src_asset_hint = self._ip_alias.get(sip)
            if src_asset_hint and src_asset_hint in self.assets:
                a = self.assets[src_asset_hint]
                prev = a.attrs.get("_ttl_max", 0)
                if ip.ttl > prev:
                    a.attrs["_ttl_max"] = ip.ttl
                    guess = next((t for t in (64, 128, 255) if ip.ttl <= t), 255)
                    a.attrs["inferred_hops"] = max(0, guess - ip.ttl)
                    a.attrs["ttl_initial_guess"] = guess

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            raw = bytes(tcp.payload)
            if not raw:
                return False
            sp, dp = tcp.sport, tcp.dport
            if dp == 1883 or sp == 1883:
                return self._on_mqtt(sip, dip, sp, dp, raw, ts)
            if dp == 502 or sp == 502:
                return self._on_modbus(sip, dip, sp, dp, raw, ts)
            if dp == 102 or sp == 102:
                return self._on_s7(sip, dip, sp, dp, raw, ts)
            if dp == 44818 or sp == 44818:
                return self._on_enip(sip, dip, sp, dp, raw, ts)
            if dp == 20000 or sp == 20000:
                return self._on_dnp3(sip, dip, sp, dp, raw, ts)
            if dp == 4840 or sp == 4840:
                return self._on_opcua(sip, dip, sp, dp, raw, ts)
            return False
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            raw = bytes(udp.payload)
            sp, dp = udp.sport, udp.dport
            if dp == 47808 or sp == 47808:
                return self._on_bacnet(sip, dip, sp, dp, raw, ts)
            if dp == 137 or sp == 137:
                return self._on_nbns(sip, raw, ts)
            if dp == 67 or dp == 68 or sp == 67 or sp == 68:
                return self._on_dhcp(src_mac, raw, ts)
            if dp == 5353 or sp == 5353:
                return self._on_mdns(sip, raw, ts)
            if dp == 1900 or sp == 1900:
                return self._on_ssdp(sip, raw, ts)
            if dp == 3671 or sp == 3671:
                return self._on_knx(sip, raw, ts)
        return False

    # -- dissectors ------------------------------------------------------------

    # --- smart-building / IoT -------------------------------------------------
    def _read_dns_name(self, raw: bytes, off: int) -> tuple[str, int]:
        """Decode a (non-compressed) DNS name; returns (name, next_offset)."""
        labels = []
        while off < len(raw):
            ln = raw[off]
            off += 1
            if ln == 0:
                break
            labels.append(raw[off:off + ln].decode("utf-8", "replace"))
            off += ln
        return ".".join(labels), off

    def _on_mdns(self, sip: str, raw: bytes, ts: str) -> bool:
        if len(raw) < 12:
            return False
        try:
            qr = (raw[2] >> 7) & 1
            qd, an = struct.unpack(">H", raw[4:6])[0], struct.unpack(">H", raw[6:8])[0]
            ns, ar = struct.unpack(">H", raw[8:10])[0], struct.unpack(">H", raw[10:12])[0]
        except struct.error:
            return False
        a = self.resolve(ip=sip)
        a.protocols.add("mdns")
        a.touch(ts)
        if qr == 0:
            a.roles.add("mdns_querier")
        # walk all records (answer/authority/additional)
        off = 12
        for _ in range(qd):
            _, off = self._read_dns_name(raw, off)
            off += 4
        for _ in range(an + ns + ar):
            if off + 10 > len(raw):
                break
            name, off = self._read_dns_name(raw, off)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", raw[off:off + 10])
            off += 10
            rdata = raw[off:off + rdlen]
            off += rdlen
            if rtype == 12 and name.endswith(".local"):
                # PTR: instance is in the record NAME (Instance._svc._tcp.local),
                # rdata points at the service type.
                inst = name.split(".")[0]
                svc = name.split(".", 1)[1] if "." in name else ""
                if inst and svc:
                    a.hostnames.add(inst)
                    a.attrs.setdefault("mdns_services", [])
                    if svc not in a.attrs["mdns_services"]:
                        a.attrs["mdns_services"].append(svc)
                a.roles.add("iot_device")
                if "hap" in name:
                    a.attrs["iot_platform"] = "HomeKit"
            elif rtype == 33:  # SRV
                a.roles.add("iot_device")
            elif rtype == 16:  # TXT: one or more length-prefixed strings
                i2 = 0
                while i2 < len(rdata):
                    sl = rdata[i2]
                    i2 += 1
                    s = rdata[i2:i2 + sl].decode("utf-8", "replace")
                    i2 += sl
                    if s.startswith("md="):
                        a.attrs["model"] = s[3:]
                    elif s.startswith("id="):
                        a.attrs["device_id"] = s[3:]
        return True

    def _on_ssdp(self, sip: str, raw: bytes, ts: str) -> bool:
        try:
            head = raw[:600].decode("utf-8", "replace")
        except Exception:
            return False
        if "HTTP/1.1" not in head.split("\r\n")[0] and "HTTP/1.0" not in head.split("\r\n")[0]:
            return False
        a = self.resolve(ip=sip)
        a.protocols.add("ssdp")
        a.touch(ts)
        a.roles.add("iot_device")
        for line in head.split("\r\n"):
            if line.lower().startswith("server:"):
                a.attrs["upnp_server"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("usn:"):
                a.attrs["upnp_usn"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("nt:"):
                a.attrs["upnp_nt"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("st:") and "ssdp:discover" not in line:
                a.attrs["upnp_st"] = line.split(":", 1)[1].strip()
        return True

    def _on_mqtt(self, sip, dip, sp, dp, raw, ts) -> bool:
        if not raw:
            return False
        ptype = raw[0] >> 4
        r = self._conv(sip, dip, "mqtt", ts, server_port=1883, sport=sp, dport=dp)
        if r is None:
            return True
        client, server, e = r
        client.roles.add("mqtt_client")
        server.roles.add("mqtt_broker")
        if ptype == 1:  # CONNECT: client-id in payload
            try:
                # fixed hdr(1) + remaining len (assume <128) + proto name len(2)
                i = 2
                namelen = struct.unpack(">H", raw[i:i + 2])[0]
                i += 2 + namelen + 4          # name, level, flags, keepalive
                cidlen = struct.unpack(">H", raw[i:i + 2])[0]
                cid = raw[i + 2:i + 2 + cidlen].decode("utf-8", "replace")
                if cid:
                    client.attrs["mqtt_client_id"] = cid
                    client.hostnames.add(cid)
            except (struct.error, IndexError):
                pass
        elif ptype == 3:  # PUBLISH: topic name after remaining-length byte
            try:
                tlen = struct.unpack(">H", raw[2:4])[0]
                topic = raw[4:4 + tlen].decode("utf-8", "replace")
                if topic:
                    client.attrs.setdefault("mqtt_topics", [])
                    if topic not in client.attrs["mqtt_topics"]:
                        client.attrs["mqtt_topics"].append(topic)
            except (struct.error, IndexError):
                pass
        return True

    def _on_knx(self, sip: str, raw: bytes, ts: str) -> bool:
        if len(raw) < 6 or raw[0] != 6 or raw[1] != 0x10:
            return False
        svc = struct.unpack(">H", raw[2:4])[0]
        a = self.resolve(ip=sip)
        a.protocols.add("knxnet_ip")
        a.touch(ts)
        if svc == 0x0201:
            a.roles.add("knx_client")
        elif svc == 0x0202:
            a.roles.add("knx_gateway")
            # walk DIBs for device name
            off = 6 + 8  # header + HPAI
            while off + 2 <= len(raw):
                dlen, dtype = raw[off], raw[off + 1]
                if dlen < 2:
                    break
                if dtype == 0x02 and dlen > 6:
                    # friendly-name DIB: name follows medium/status/address
                    nm = raw[off + 6:off + dlen].split(b"\x00")[0].decode("utf-8", "replace")
                    if nm and nm.isprintable():
                        a.hostnames.add(nm)
                        a.attrs["knx_friendly_name"] = nm
                off += dlen
        return True

    def _conv(self, sip: str, dip: str, proto: str, ts="", server_port: int | None = None,
              sport: int = 0, dport: int = 0):
        """Resolve client & server assets for a conversation frame. Returns
        (client, server, edge client->server) or None for broadcast flows.
        Responses are attributed to the same client->server edge (no reverse edge)."""
        if dip.endswith(".255") or dip == "255.255.255.255" or dip.startswith("224.") or dip.startswith("239."):
            src = self.resolve(ip=sip)
            src.protocols.add(proto)
            src.touch(ts)
            return None
        s = self.resolve(ip=sip)
        d = self.resolve(ip=dip)
        s.protocols.add(proto)
        d.protocols.add(proto)
        s.touch(ts)
        d.touch(ts)
        # orientation: the endpoint at the well-known OT port is the server
        if dport and dport == server_port:
            client, server = s, d
        elif sport and sport == server_port:
            client, server = d, s
        else:
            client, server = s, d
        e = self.edge(client.id, server.id, proto)
        e.touch(ts)
        return (client, server, e)

    def _on_modbus(self, sip, dip, sp, dp, raw, ts) -> bool:
        if len(raw) < 8:
            return False
        proto_id = struct.unpack(">H", raw[2:4])[0]
        if proto_id != 0:
            return False
        unit = raw[6]
        fc = raw[7]
        r = self._conv(sip, dip, "modbus", ts, server_port=502, sport=sp, dport=dp)
        if r is None:
            return True
        client, server, e = r
        client.roles.add("master")
        server.roles.add("modbus_slave")
        if dp == 502:                       # request
            # unit-id stats: unit 0 = raw serial passthrough, 255 = gateway self
            if unit not in (0, 255):
                st = self._mb_units.setdefault((server.id, unit), {"pkts": 0, "writes": 0})
                st["pkts"] += 1
                if fc in MODBUS_WRITE_FCS:
                    st["writes"] += 1
            if fc in MODBUS_WRITE_FCS:
                e.writes += 1
        else:                               # response
            if fc & 0x80:
                e.exceptions += 1
                server.attrs["modbus_exceptions"] = server.attrs.get("modbus_exceptions", 0) + 1
        return True

    def _on_s7(self, sip, dip, sp, dp, raw, ts) -> bool:
        if len(raw) < 10 or raw[0] != 3:
            return False
        r = self._conv(sip, dip, "s7comm", ts, server_port=102, sport=sp, dport=dp)
        if r is None:
            return True
        client, server, e = r
        client.roles.add("master")
        server.roles.add("s7_slave")
        if dp == 102 and len(raw) >= 22:
            param = raw[17:]
            if len(param) >= 4 and param[0] == 0x12 and param[3] == 0x01:
                e.writes += 1
        return True

    def _on_enip(self, sip, dip, sp, dp, raw, ts) -> bool:
        if len(raw) < 24:
            return False
        cmd = struct.unpack("<H", raw[0:2])[0]
        r = self._conv(sip, dip, "enip", ts, server_port=44818, sport=sp, dport=dp)
        if r is None:
            return True
        client, server, e = r
        client.roles.add("master")
        server.roles.add("enip_slave")
        if cmd == 0x63 and sp == 44818 and len(raw) > 61:
            # listIdentity response: identity object at 24+6+16=46
            # CIP identity: vendor(2) devtype(2) prodcode(2) rev(2) status(2)
            #               serial(4)@10 namelen(1)@14 name@15
            try:
                ident = raw[46:]
                vendor = struct.unpack("<H", ident[0:2])[0]
                serial = struct.unpack("<I", ident[10:14])[0]
                namelen = ident[14]
                name = ident[15:15 + namelen].decode("latin1", "replace")
                if name:
                    server.attrs["enip_product"] = name
                    server.attrs["enip_vendor_id"] = vendor
                    server.attrs["enip_serial"] = f"0x{serial:08X}"
            except (struct.error, IndexError):
                pass
        return True

    def _on_dnp3(self, sip, dip, sp, dp, raw, ts) -> bool:
        if len(raw) < 10 or raw[0:2] != b"\x05\x64":
            return False
        r = self._conv(sip, dip, "dnp3", ts, server_port=20000, sport=sp, dport=dp)
        if r is None:
            return True
        client, server, e = r
        if dp == 20000:                     # request frames only
            try:
                dst, src = struct.unpack("<HH", raw[4:8])
                client.attrs["dnp3_link_addr"] = src
                server.attrs.setdefault("dnp3_link_addr", dst)
                st = self._dnp_links.setdefault((server.id, dst), {"pkts": 0})
                st["pkts"] += 1
            except struct.error:
                pass
        client.roles.add("master")
        server.roles.add("dnp3_outstation")
        return True

    def _on_opcua(self, sip, dip, sp, dp, raw, ts) -> bool:
        if len(raw) < 8 or raw[0:4] not in (b"HELF", b"OPNF", b"MSGF", b"ERRF", b"CLOF"):
            return False
        r = self._conv(sip, dip, "opcua", ts, server_port=4840, sport=sp, dport=dp)
        if r is None:
            return True
        client, server, e = r
        if raw[0:4] == b"HELF":
            # HEL: magic(4) size(4) scid(4) proto(4) recv(4) send(4) maxmsg(4)
            #      maxchunk(4) urllen(4) url
            try:
                off = 36
                urllen = struct.unpack("<I", raw[32:36])[0]
                if 0 < urllen < 200 and len(raw) >= off + urllen:
                    url = raw[off:off + urllen].decode("utf-8", "replace")
                    server.attrs["opcua_url"] = url
            except (struct.error, IndexError):
                pass
        client.roles.add("opcua_client")
        server.roles.add("opcua_server")
        return True

    def _on_bacnet(self, sip, dip, sp, dp, raw, ts) -> bool:
        if len(raw) < 8 or raw[0] != 0x81:
            return False
        r = self._conv(sip, dip, "bacnet", ts)
        # npdu control byte: skip destination/hop fields if present
        npdu_ctl = raw[5] if len(raw) > 5 else 0
        off = 6
        if npdu_ctl & 0x20:
            dlen = raw[off]
            off += 1 + dlen + 1
        src_asset = self.resolve(ip=sip)
        src_asset.roles.add("bacnet_device")
        if r is not None:
            _, d, e = r
            d.roles.add("bacnet_device")
        if len(raw) > off + 1:
            apdu_type = raw[off] >> 4
            service = raw[off + 1]
            if apdu_type == 1 and service == 0x00 and len(raw) >= off + 8:
                # i-am: objid ctx-tag at off+2, objid at off+3
                objid = struct.unpack(">I", raw[off + 3: off + 7])[0]
                src_asset.attrs["bacnet_instance"] = objid & 0x3FFFFF
        return True

    def _on_lldp(self, src_mac: str, payload: bytes, ts: str) -> bool:
        a = self.resolve(mac=src_mac)
        a.touch(ts)
        a.protocols.add("lldp")
        i, n = 0, len(payload)
        caps = 0
        while i + 2 <= n:
            hdr = struct.unpack(">H", payload[i:i + 2])[0]
            t, l = hdr >> 9, hdr & 0x1FF
            val = payload[i + 2: i + 2 + l]
            i += 2 + l
            if t == 0:
                break
            if t == 5:
                name = val.decode("latin1", "replace").strip()
                if name:
                    a.hostnames.add(name)
                    a.attrs["lldp_sysname"] = name
            elif t == 7 and len(val) >= 2:
                caps = struct.unpack(">H", val[0:2])[0]
            elif t == 8 and len(val) >= 7 and val[1] == 1:
                # management address TLV: len(1) subtype(1) addr...
                ipaddr = str(ip_address(val[2:6]))
                a.ips.add(ipaddr)
                self._ip_alias[ipaddr] = a.id
        if caps & 0x10:
            a.roles.add("gateway")
            a.roles.add("router")
        if caps & 0x04:
            a.roles.add("switch")
        if caps & 0x20:
            a.roles.add("voip_phone")   # telephone bit
        return True

    def _on_profinet(self, src_mac: str, dst_mac: str, payload: bytes, ts: str) -> bool:
        if len(payload) < 4:
            return False
        fid = struct.unpack(">H", payload[0:2])[0]
        if fid == 0x0E5D:   # DCP identify response
            a = self.resolve(mac=src_mac)
            a.touch(ts)
            a.protocols.add("profinet_dcp")
            i = 14  # frameid(2) res(2) service(2) xid(4) resp(2) len(2)
            end = len(payload)
            while i + 4 <= end:
                opt, sub = payload[i], payload[i + 1]
                blen = struct.unpack(">H", payload[i + 2:i + 4])[0]
                val = payload[i + 4:i + 4 + blen]
                i += 4 + blen
                if opt == 0x03 and sub == 0x02:
                    name = val.decode("latin1", "replace").strip()
                    if name:
                        a.hostnames.add(name)
                        a.attrs["pn_station"] = name
                elif opt == 0x02 and sub == 0x01 and blen >= 12:
                    ipaddr = str(ip_address(val[0:4]))
                    a.ips.add(ipaddr)
                    self._ip_alias[ipaddr] = a.id
                elif opt == 0x03 and sub == 0x05 and val:
                    role = val[0]
                    if role & 0x01:
                        a.roles.add("pn_io_device")
                    if role & 0x02:
                        a.roles.add("pn_io_controller")
            return True
        if 0x8000 <= fid <= 0xBFFF:    # real-time cyclic data
            s = self.resolve(mac=src_mac)
            d = self.resolve(mac=dst_mac)
            s.protocols.add("profinet_rt")
            d.protocols.add("profinet_rt")
            s.touch(ts)
            d.touch(ts)
            e = self.edge(s.id, d.id, "profinet_rt")
            e.touch(ts)
            return True
        return False

    def _on_arp(self, arp, ts: str) -> bool:
        if arp.op in (1, 2):
            if arp.psrc and str(arp.hwsrc) != "00:00:00:00:00:00":
                self.bind(arp.psrc, str(arp.hwsrc)).touch(ts)
            return True
        return False

    def _on_nbns(self, sip: str, raw: bytes, ts: str) -> bool:
        if len(raw) < 46:
            return False
        # first-level decoded name at offset 12, 32 bytes
        enc = raw[12:44]
        out = []
        ok = True
        for i in range(0, 32, 2):
            hi, lo = enc[i] - 65, enc[i + 1] - 65
            if not (0 <= hi <= 15 and 0 <= lo <= 15):
                ok = False
                break
            c = (hi << 4) | lo
            if c == 0:
                break
            if 32 <= c < 127:
                out.append(chr(c))
        if not ok or not out:
            return False
        name = "".join(out).strip()
        if not name or len(name) < 2:
            return False
        flags = struct.unpack(">H", raw[2:4])[0]
        is_registration = (flags & 0x7800) != 0   # registration or refresh or release
        if is_registration:
            a = self.resolve(ip=sip)
            a.hostnames.add(name)
            a.attrs["nbns_name"] = name
            a.touch(ts)
        return True

    def _on_dhcp(self, src_mac: str, raw: bytes, ts: str) -> bool:
        if len(raw) < 240:
            return False
        i = raw.find(b"\x63\x82\x53\x63", 228)
        if i < 0:
            return False
        chaddr = raw[28:34]
        mac = ":".join(f"{b:02x}" for b in chaddr)
        opts = raw[i + 4:]
        j = 0
        hostname = ""
        while j + 1 < len(opts) and opts[j] != 255:
            code, ln = opts[j], opts[j + 1]
            if code == 12:
                hostname = opts[j + 2:j + 2 + ln].decode("latin1", "replace").strip()
            j += 2 + ln
        target = None
        if src_mac and src_mac != "ff:ff:ff:ff:ff:ff":
            target = self.resolve(mac=src_mac)
        elif mac != "00:00:00:00:00:00":
            target = self.resolve(mac=mac)
        if target is not None:
            target.protocols.add("dhcp")
            target.touch(ts)
            if hostname:
                target.hostnames.add(hostname)
                target.attrs["dhcp_hostname"] = hostname
        return True

    # -- inference ---------------------------------------------------------------
    def attack_paths(self, max_depth: int = 8) -> list[dict]:
        """BFS from enterprise-zone masters to PLC/RTU assets across ALL edges
        (including gateway bridges). Returns hop-by-hop paths — observed
        conversations only, not confirmed reachability."""
        sc = self.scope
        adj = {}
        for e in self.edges.values():
            adj.setdefault(e.src, set()).add((e.dst, e.proto))
            adj.setdefault(e.dst, set()).add((e.src, e.proto))
        starts = [a for a in self.assets.values()
                  if sc.purdue_of(a.zone(sc)) == "L4/L5" and "master" in a.roles]
        targets = [a for a in self.assets.values() if a.roles & {"plc", "rtu"}]
        target_ids = {t.id for t in targets}
        paths = []
        for s in starts:
            # BFS
            prev = {s.id: None}
            q = [s.id]
            while q:
                cur = q.pop(0)
                for nxt, proto in adj.get(cur, ()):  # undirected traversal
                    if nxt in prev:
                        continue
                    prev[nxt] = (cur, proto)
                    q.append(nxt)
            for t in target_ids:
                if t not in prev or t == s.id:
                    continue
                hops, cur = [], t
                while prev[cur] is not None:
                    p, proto = prev[cur]
                    hops.append((p, cur, proto))
                    cur = p
                hops.reverse()
                paths.append({"from": s.id, "to": t, "hops": hops, "depth": len(hops)})
        paths.sort(key=lambda p: p["depth"])
        return paths

    def next_crawl_targets(self) -> list[dict]:
        """Where the next discovery round should look, based on what the graph
        already knows: out-of-scope subnets seen in conversations, subnets
        behind routers/gateways, and gateway/concentrator assets whose
        children suggest deeper enumeration. Read-only analysis of state."""
        targets = []
        sc = self.scope
        # 1. out-of-scope / unclassified subnets actively talking
        for e in self.edges.values():
            for aid in (e.src, e.dst):
                a = self.assets.get(aid)
                if a is None:
                    continue
                for ip in a.ips:
                    z = sc.zone_of(ip)
                    if z in ("Unclassified", "Excluded") and not any(t["ip"] == ip for t in targets):
                        targets.append({"ip": ip, "reason": f"active conversation, zone={z}",
                                        "via": e.proto})
        # 2. routed subnets: assets behind a last-hop router have neighbors we
        #    have not seen yet on their subnet
        for a in self.assets.values():
            rtr = a.attrs.get("last_hop_router")
            if rtr:
                for ip in a.ips:
                    sub = ip.rsplit(".", 1)[0]
                    if not any(t["ip"].startswith(sub + ".") for t in targets):
                        targets.append({"ip": f"{sub}.0/24", "reason": f"routed subnet behind {rtr}",
                                        "via": "ttl"})
        # 3. gateway assets: deeper unit/link enumeration candidates
        for a in self.assets.values():
            if "modbus_gateway" in a.roles or "dnp3_concentrator" in a.roles:
                for ip in a.ips:
                    if not any(t["ip"] == ip for t in targets):
                        targets.append({"ip": ip, "reason": "gateway/concentrator — enumerate units/links",
                                        "via": "gateway"})
        return targets

    def infer_roles(self):
        sc = self.scope
        for a in self.assets.values():
            if "modbus_slave" in a.roles or "s7_slave" in a.roles or "enip_slave" in a.roles:
                a.roles.add("plc")
            if "dnp3_outstation" in a.roles:
                a.roles.add("rtu")
            z = a.zone(sc)
            if "master" in a.roles:
                if z == "Enterprise":
                    a.roles.add("engineering_ws")
                elif z in ("L2", "L3", "L2_L3"):
                    a.roles.add("scada_server")
            if "opcua_server" in a.roles and "master" not in a.roles and "plc" not in a.roles:
                a.roles.add("opcua_server_only")
            if "bacnet_device" in a.roles and not (a.roles & {"plc", "master", "scada_server"}):
                a.roles.add("building_controller")

    def compute_findings(self):
        sc = self.scope
        self.findings = []
        f = self.findings

        for a in sorted(self.assets.values(), key=lambda x: x.id):
            z = a.zone(sc)
            if a.is_unmanaged(sc):
                unmanaged_master = "master" in a.roles
                f.append({
                    "id": f"unmanaged-{a.id}",
                    "severity": "high" if unmanaged_master else "medium",
                    "title": f"Unmanaged {'master ' if unmanaged_master else ''}device in OT zone ({z}): {a.label}",
                    "assets": [a.id],
                    "evidence": {
                        "vendor": a.vendor, "mac": a.mac, "ips": sorted(a.ips),
                        "protocols": sorted(a.protocols & OT_PROTOCOLS),
                        "zone": z,
                    },
                    "description": (
                        f"Consumer/vendor-class device ({a.vendor or 'unknown vendor'}) observed in {z}. "
                        + ("It is issuing control-protocol commands (master role) — unplanned OT write path. "
                           if unmanaged_master else
                           "Presence in the control zone suggests an unmanaged engineering or contractor asset.")
                    ),
                })
            # IoT/smart-building devices in an OT zone (or talking to one)
            if a.roles & IOT_ROLES:
                talks_to_control = any(
                    e.src == a.id and self.assets.get(e.dst) is not None
                    and self.assets[e.dst].zone(sc) in OT_ZONES
                    for e in self.edges.values()) or z in OT_ZONES
                if talks_to_control:
                    f.append({
                        "id": f"iot-ot-{a.id}",
                        "severity": "medium",
                        "title": f"IoT/smart-building device on OT network: {a.label} ({a.vendor or '?'})",
                        "assets": [a.id],
                        "evidence": {
                            "vendor": a.vendor, "mac": a.mac, "ips": sorted(a.ips),
                            "protocols": sorted(a.protocols & (OT_PROTOCOLS | IOT_PROTOCOLS)),
                            "attrs": {k: v for k, v in a.attrs.items()
                                      if k in ("model", "upnp_server", "mdns_services", "iot_platform")},
                        },
                        "description": (
                            "Consumer smart-device protocol traffic (mDNS/SSDP/MQTT/KNX/HomeKit) observed "
                            + (f"inside {z} — " if z in OT_ZONES else "communicating with the OT network — ")
                            + "a thermostat/hub/sensor bridged onto the control network is a common "
                              "flat-network finding and a wireless-to-OT pivot path."
                        ),
                    })

        for e in self.edges.values():
            if e.proto not in OT_PROTOCOLS:
                continue
            src = self.assets.get(e.src)
            dst = self.assets.get(e.dst)
            if src is None or dst is None:
                continue
            sz, dz = src.zone(sc), dst.zone(sc)
            if sz in ("Enterprise", "L4", "L5") and dz in ("L1", "L2", "L3", "L2_L3"):
                f.append({
                    "id": f"ent2ctl-{e.src}-{e.dst}-{e.proto}",
                    "severity": "high",
                    "title": f"Enterprise-to-control path: {src.label} -> {dst.label} ({e.proto})",
                    "assets": [e.src, e.dst],
                    "evidence": {"proto": e.proto, "count": e.count,
                                 "src_zone": sz, "dst_zone": dz},
                    "description": (
                        f"Direct {e.proto} session from enterprise zone ({sz}) into control zone ({dz}) "
                        "bypassing the Purdue DMZ segmentation boundary."
                    ),
                })
            if e.writes:
                f.append({
                    "id": f"writes-{e.src}-{e.dst}-{e.proto}",
                    "severity": "info",
                    "title": f"Control writes observed: {src.label} -> {dst.label} ({e.proto}, {e.writes} write requests)",
                    "assets": [e.src, e.dst],
                    "evidence": {"proto": e.proto, "writes": e.writes},
                    "description": "Write-class function codes observed on the wire (normal for masters, but map and confirm intent).",
                })

    # -- graph / export -----------------------------------------------------------
    def to_graph(self) -> dict:
        sc = self.scope
        nodes = [a.to_dict(sc) for a in self.assets.values()]
        links = [e.to_dict() for e in self.edges.values()]
        return {"nodes": nodes, "links": links, "findings": self.findings,
                "generated": now_iso(), "scope": sc.data.get("name")}

    def to_dot(self) -> str:
        sc = self.scope
        ZONE_COLORS = {"L1": "#8b6f47", "L2_L3": "#4a7a8c", "L2": "#4a7a8c", "L3": "#4a7a8c",
                       "Enterprise": "#7a4a8c", "L4/L5": "#7a4a8c"}
        ROLE_SHAPES = {"plc": "box", "rtu": "box", "switch": "hexagon", "gateway": "tripleoctagon",
                       "scada_server": "cylinder", "engineering_ws": "rect", "master": "diamond"}
        lines = ["digraph downstream {", '  rankdir=LR;', '  bgcolor="#111318";',
                 '  node [style="filled,solid" fontname="Helvetica" fontcolor="#e8e8e8" color="#3a3f4b"];',
                 '  edge [fontname="Helvetica" fontcolor="#9aa0ad" color="#5a6070"];']
        zones = {}
        for a in self.assets.values():
            z = a.zone(sc)
            zones.setdefault(z, []).append(a)
        for z, assets in zones.items():
            lines.append(f'  subgraph cluster_{z.replace("/", "_")} {{')
            lines.append(f'    label="{z}"; fontsize=16; color="#3a3f4b"; fontcolor="#c8cdd6";')
            for a in assets:
                shape = "ellipse"
                for r, s in ROLE_SHAPES.items():
                    if r in a.roles:
                        shape = s
                        break
                color = ZONE_COLORS.get(z, "#555")
                extra = ', color="#e05252"' if a.is_unmanaged(sc) else ""
                label = a.label
                if a.vendor:
                    label += f"\\n{a.vendor[:24]}"
                label += f"\\n{','.join(sorted(a.protocols & OT_PROTOCOLS))[:40]}" if (a.protocols & OT_PROTOCOLS) else ""
                lines.append(f'    "{a.id}" [label="{label}", fillcolor="{color}", shape={shape}{extra}];')
            lines.append("  }")
        for e in self.edges.values():
            if e.proto not in OT_PROTOCOLS and e.proto != "profinet_rt":
                continue
            attrs = []
            if e.writes:
                attrs.append(f'w:{e.writes}')
            if e.exceptions:
                attrs.append(f'exc:{e.exceptions}')
            lab = e.proto + (" (" + " ".join(attrs) + ")" if attrs else "")
            color = "#e05252" if e.writes else "#5a6070"
            lines.append(f'  "{e.src}" -> "{e.dst}" [label="{lab}", color="{color}"];')
        lines.append("}")
        return "\n".join(lines)

    def assets_csv(self) -> str:
        sc = self.scope
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["label", "ips", "mac", "vendor", "hostnames", "roles", "zone", "purdue",
                    "protocols", "pkt_count", "unmanaged", "first_seen", "last_seen"])
        for a in sorted(self.assets.values(), key=lambda x: x.id):
            d = a.to_dict(sc)
            w.writerow([d["label"], " ".join(d["ips"]), d["mac"], d["vendor"],
                        " ".join(d["hostnames"]), " ".join(d["roles"]), d["zone"], d["purdue"],
                        " ".join(d["protocols"]), d["pkt_count"], d["unmanaged"],
                        d["first_seen"], d["last_seen"]])
        return buf.getvalue()

    def edges_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["source", "target", "proto", "count", "writes", "exceptions"])
        for e in self.edges.values():
            w.writerow([e.src, e.dst, e.proto, e.count, e.writes, e.exceptions])
        return buf.getvalue()

    def report_md(self) -> str:
        sc = self.scope
        lines = [f"# Downstream OT asset report", "",
                 f"- Generated: {now_iso()}", f"- Scope: {sc.data.get('name')}",
                 f"- Assets: {len(self.assets)}  Conversations: {len(self.edges)}  Findings: {len(self.findings)}",
                 "", "## Findings", ""]
        for f in sorted(self.findings, key=lambda x: {"high": 0, "medium": 1, "info": 2}.get(x["severity"], 3)):
            lines += [f"### [{f['severity'].upper()}] {f['title']}", "",
                      f["description"], "",
                      f"- Evidence: `{json.dumps(f['evidence'], default=str)}`", ""]
        lines += ["## Assets", "", "| Label | IPs | Vendor | Roles | Zone | Protocols | Unmanaged |",
                  "|---|---|---|---|---|---|---|"]
        for a in sorted(self.assets.values(), key=lambda x: x.id):
            d = a.to_dict(sc)
            lines.append(f"| {d['label']} | {', '.join(d['ips']) or d['mac']} | {d['vendor']} | "
                         f"{', '.join(d['roles']) or '-'} | {d['zone']} | {', '.join(d['protocols'])} | "
                         f"{'**YES**' if d['unmanaged'] else ''} |")
        lines += ["", "## Conversations", "",
                  "| Source | Destination | Protocol | Frames | Writes | Exceptions |",
                  "|---|---|---|---|---|---|"]
        for e in sorted(self.edges.values(), key=lambda x: (x.proto, -x.count)):
            lines.append(f"| {self.assets.get(e.src).label if self.assets.get(e.src) else e.src} "
                         f"| {self.assets.get(e.dst).label if self.assets.get(e.dst) else e.dst} "
                         f"| {e.proto} | {e.count} | {e.writes} | {e.exceptions} |")
        # multi-layer attack paths
        paths = self.attack_paths()
        if paths:
            lbl = {a.id: a.label for a in self.assets.values()}
            lines += ["", "## Enterprise-to-PLC paths (observed conversations)", "",
                      "Paths traverse gateways and concentrators; each hop is a directly "
                      "observed conversation, not confirmed reachability.", ""]
            for p in paths:
                route = " -> ".join([lbl.get(p["from"], p["from"])] +
                                    [lbl.get(h[1], h[1]) for h in p["hops"]])
                protos = "+".join(dict.fromkeys(h[2] for h in p["hops"]))
                lines.append(f"- **{p['depth']} hops** ({protos}): {route}")
        lines += ["", "## Limitations / non-claims",
                  "", "- Passive graph edges are observed conversations, not confirmed control paths.",
                  "- Roles are protocol-behavior inferences; validate before reporting to the client.",
                  "- Active probes are read-only discovery; no write-class traffic is ever sent."]
        return "\n".join(lines)

    def recompute(self):
        self._materialize_gateway_children()
        self.infer_roles()
        self.compute_findings()

    def _materialize_gateway_children(self):
        """Spawn virtual child assets for control devices behind gateways.

        Modbus: a server polled at >1 unit ID is a gateway; every unit ID
        becomes a child PLC (the lowest observed unit is likely the gateway's
        own port, but conservative mapping keeps them all as children).
        DNP3: a server receiving >1 distinct destination link address is a data
        concentrator; each non-lowest link address becomes a child outstation."""
        # modbus units per gateway
        per_gw: dict[str, set[int]] = {}
        for (sid, unit), st in self._mb_units.items():
            if st["pkts"] >= 1:
                per_gw.setdefault(sid, set()).add(unit)
        for sid, units in per_gw.items():
            gw = self.assets.get(sid)
            if gw is None or len(units) < 2:
                continue          # single unit = the device itself
            gw.roles.add("modbus_gateway")
            for unit in sorted(units):
                self._spawn_child(gw, f"u{unit}", "modbus", unit=unit)
        # dnp3 links per concentrator
        per_dc: dict[str, set[int]] = {}
        for (sid, link), st in self._dnp_links.items():
            per_dc.setdefault(sid, set()).add(link)
        for sid, links in per_dc.items():
            dc = self.assets.get(sid)
            if dc is None or len(links) < 2:
                continue
            dc.roles.add("dnp3_concentrator")
            own = min(links)      # lowest link = the concentrator's own port
            for link in sorted(links):
                if link == own:
                    continue
                self._spawn_child(dc, f"d{link}", "dnp3", link=link)

    def _spawn_child(self, gw: Asset, tag: str, proto: str, unit=None, link=None):
        child_id = f"{gw.id}#{tag}"
        child = self.assets.get(child_id)
        if child is None:
            child = Asset()
            child.id_override = child_id
            child.protocols.add(proto)
            child.attrs["behind_gateway"] = gw.id
            child._parent_asset = gw
            self.assets[child_id] = child
        if proto == "modbus":
            child.roles.update({"plc", "modbus_slave"})
            child.attrs["modbus_unit"] = unit
        else:
            child.roles.update({"rtu", "dnp3_outstation"})
            child.attrs["dnp3_link_addr"] = link
        # gateway bridges to child; masters reach children through it
        self.edge(gw.id, child_id, f"{proto}_bridge").count += 1
        for e in list(self.edges.values()):
            if e.proto == proto and e.dst == gw.id and e.src != child_id:
                ce = self.edge(e.src, child_id, proto)
                ce.count += 1
                st = self._mb_units.get((gw.id, unit), {}) if proto == "modbus" else {}
                ce.writes += st.get("writes", 0)

    # -- persistence ------------------------------------------------------------
    def save(self, path: str | Path):
        state = {
            "scope": self.scope.data,
            "assets": [a.to_dict(self.scope) for a in self.assets.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "findings": self.findings,
            "events": self.events[-500:],
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(state, f, indent=1)

    @classmethod
    def load(cls, path: str | Path) -> "Model":
        with open(path) as f:
            state = json.load(f)
        m = cls(Scope(state.get("scope") or None))
        for d in state.get("assets", []):
            a = Asset(mac=d.get("mac", ""))
            a.id_override = d.get("id", "")
            if a.id_override == a.mac:
                a.id_override = ""
            a.ips = set(d.get("ips", []))
            a.vendor = d.get("vendor", "")
            if not a.vendor:
                a._refresh_vendor()
            a.hostnames = set(d.get("hostnames", []))
            a.protocols = set(d.get("protocols", []))
            a.roles = set(d.get("roles", []))
            a.attrs = d.get("attributes", {})
            a.pkt_count = d.get("pkt_count", 0)
            a.first_seen = d.get("first_seen", "")
            a.last_seen = d.get("last_seen", "")
            m.assets[a.id] = a
            for ip in a.ips:
                m._ip_alias[ip] = a.id
        # re-link virtual children to their gateways
        for a in m.assets.values():
            gw_id = a.attrs.get("behind_gateway")
            if gw_id and gw_id in m.assets:
                a._parent_asset = m.assets[gw_id]
        for d in state.get("edges", []):
            e = Edge(d["source"], d["target"], d["proto"])
            e.count = d.get("count", 0)
            e.writes = d.get("writes", 0)
            e.exceptions = d.get("exceptions", 0)
            m.edges[e.key()] = e
        m.findings = state.get("findings", [])
        m.events = state.get("events", [])
        # re-derive roles/findings under the CURRENT scope (state may have been
        # captured under a different or absent scope)
        m.infer_roles()
        m.compute_findings()
        return m

# --------------------------------------------------------------------------
# Active layer (gated)
# --------------------------------------------------------------------------

# Registry: ONLY read-only discovery techniques exist. Write-class probes are
# deliberately not implemented; requesting an unknown technique is a hard block.
ACTIVE_TECHNIQUES = {"arp_ping", "tcp_probe", "modbus_id", "enip_list", "mdns_query", "ssdp_msearch", "modbus_unit_sweep"}


class ActivePlanner:
    def __init__(self, scope: Scope):
        self.scope = scope

    def target_ips(self) -> list[str]:
        ips = []
        for net, zone in self.scope.zone_nets:
            if zone == "Excluded":
                continue
            for ip in net.hosts():
                if not self.scope.in_scope(str(ip)):
                    continue
                ips.append(str(ip))
                if len(ips) >= 4096:
                    return ips
        return ips

    def plan(self) -> list[dict]:
        tasks = []
        for tech in sorted(ACTIVE_TECHNIQUES):
            decision = self.scope.active_decision(tech)
            if decision == "block":
                tasks.append({"technique": tech, "decision": "block",
                              "reason": "not enabled in scope active config"})
                continue
            for ip in self.target_ips():
                tasks.append({"technique": tech, "ip": ip, "decision": decision})
        return tasks


def run_active(model: Model, tasks: list[dict], execute: bool, assume_yes: bool,
               interval: float = 0.4, max_tasks: int = 512) -> dict:
    """Execute an active plan. Nothing is sent unless execute=True; 'confirm'
    decisions additionally require assume_yes. Unknown techniques: hard block."""
    results = {"sent": 0, "skipped": 0, "blocked": 0, "findings": [], "errors": []}
    if not execute:
        model.log("active", f"plan-only: {len(tasks)} tasks, nothing sent")
        results["skipped"] = len(tasks)
        return results
    done = 0
    for t in tasks:
        if done >= max_tasks:
            results["errors"].append("max task cap reached")
            break
        tech = t.get("technique")
        if tech not in ACTIVE_TECHNIQUES:
            results["blocked"] += 1
            model.log("active", f"BLOCKED unknown technique {tech!r}")
            continue
        decision = t.get("decision", "block")
        if decision == "block":
            results["blocked"] += 1
            continue
        if decision == "confirm" and not assume_yes:
            results["skipped"] += 1
            model.log("active", f"SKIPPED {tech} {t.get('ip')} (confirm not acknowledged)")
            continue
        try:
            fn = _ACTIVE_RUNNERS[tech]
            r = fn(t["ip"], model)
            results["sent"] += 1
            if r:
                results["findings"].append(r)
            done += 1
            time.sleep(interval)
        except Exception as ex:
            results["errors"].append(f"{tech} {t.get('ip')}: {ex}")
    model.log("active", f"executed {results['sent']} probes "
                        f"(skipped {results['skipped']}, blocked {results['blocked']})")
    model.infer_roles()
    model.compute_findings()
    return results


def _probe_arp(ip: str, model: Model):
    from scapy.all import ARP, srp, conf
    conf.verb = 0
    ans, _ = srp(ARP(pdst=ip), timeout=1.2, verbose=0)
    for _, rcv in ans:
        mac = str(rcv[ARP].hwsrc)
        a = model.bind(ip, mac)
        a.touch(now_iso())
        return {"ip": ip, "mac": mac, "vendor": a.vendor}
    return None


def _probe_tcp(ip: str, model: Model, ports=(502, 102, 44818, 20000, 4840, 22, 23, 80, 443)):
    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        try:
            s.connect((ip, p))
            open_ports.append(p)
        except (socket.timeout, OSError):
            pass
        finally:
            s.close()
    if open_ports:
        a = model.resolve(ip=ip)
        a.touch(now_iso())
        a.attrs["tcp_open_ports"] = sorted(set(a.attrs.get("tcp_open_ports", [])) | set(open_ports))
        return {"ip": ip, "open": open_ports}
    return None


def _probe_modbus_unit_sweep(ip: str, model: Model, port: int = 502,
                             units: range = range(1, 25), timeout: float = 0.8):
    """Enumerate Modbus unit-IDs behind a gateway: read-device-id (MEI 14) per
    unit; a response (or an exception other than 'gateway target failed to
    respond', 0x0B) proves a live PLC at that unit ID. Read-only."""
    live = []
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((ip, port))
        for unit in units:
            pdu = bytes([0x2B, 0x0E, 0x01, 0x00])      # MEI 14 read device id
            req = struct.pack(">HHHB", unit, 0, 2 + 1 + len(pdu) + 1, unit) + pdu
            try:
                s.settimeout(timeout)
                s.send(req)
                resp = s.recv(256)
            except (socket.timeout, OSError):
                continue
            if len(resp) < 9:
                continue
            fc = resp[7]
            if fc & 0x80:
                if fc != 0x8B:                          # 0x8B = gateway no-response
                    live.append((resp[6], f"exception 0x{fc:02X}"))
            else:
                live.append((resp[6], "device-id response"))
    finally:
        s.close()
    if not live:
        return None
    a = model.resolve(ip=ip)
    a.protocols.add("modbus")
    a.touch(now_iso())
    # record discovered units into the crawl stats so recompute() materializes
    # virtual child PLCs for each one
    for unit, _how in live:
        model._mb_units.setdefault((a.id, unit), {"pkts": 1, "writes": 0})
    if len(live) >= 2:
        a.roles.add("modbus_gateway")
    model.recompute()
    return {"ip": ip, "units": sorted(u for u, _ in live)}


def _probe_modbus_id(ip: str, model: Model, unit: int = 1, port: int = 502):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)


def _probe_enip_list(ip: str, model: Model, port: int = 44818):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((ip, port))
        req = struct.pack("<HHII8sI", 0x63, 0, 0, 0, b"dstrmk01", 0)
        s.send(req)
        resp = s.recv(512)
    finally:
        s.close()
    if len(resp) < 30:
        return None
    a = model.resolve(ip=ip)
    a.protocols.add("enip")
    a.roles.add("enip_slave")
    a.touch(now_iso())
    # reuse the passive dissector on the response bytes
    model._on_enip(ip, ip, port, 44818, resp, now_iso())
    return {"ip": ip, "product": a.attrs.get("enip_product", "?")}


def _probe_mdns(ip: str, model: Model):
    """One-shot multicast mDNS service enumeration (_services._dns-sd)."""
    import scapy.all as sa
    sa.conf.verb = 0
    dns = sa.DNS(id=0, rd=1, qdcount=1, qd=sa.DNSQR(qname=b"_services._dns-sd._udp.local", qtype=12))
    pkt = (sa.IP(dst="224.0.0.251") / sa.UDP(sport=5353, dport=5353) / dns)
    try:
        resp = sa.sr1(pkt, timeout=2.0, verbose=0)
    except Exception:
        resp = None
    a = model.resolve(ip=ip)
    a.protocols.add("mdns")
    a.touch(now_iso())
    if resp is not None and resp.haslayer(sa.UDP):
        model._on_mdns(ip, bytes(resp[sa.UDP].payload), now_iso())
        return {"ip": ip, "services": a.attrs.get("mdns_services", [])}
    return {"ip": ip, "result": "no mDNS response"}


def _probe_ssdp(ip: str, model: Model):
    """One-shot unicast SSDP M-SEARCH to a specific device."""
    msearch = ("M-SEARCH * HTTP/1.1\r\nHOST: {}:1900\r\nMAN: \"ssdp:discover\"\r\n"
               "MX: 2\r\nST: upnp:rootdevice\r\n\r\n").format(ip)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    try:
        s.sendto(msearch.encode(), (ip, 1900))
        data, _ = s.recvfrom(2048)
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()
    a = model.resolve(ip=ip)
    a.touch(now_iso())
    model._on_ssdp(ip, data, now_iso())
    return {"ip": ip, "upnp_server": a.attrs.get("upnp_server", "?")}


_ACTIVE_RUNNERS = {"arp_ping": _probe_arp, "tcp_probe": _probe_tcp,
                   "modbus_id": _probe_modbus_id, "enip_list": _probe_enip_list,
                   "mdns_query": _probe_mdns, "ssdp_msearch": _probe_ssdp,
                   "modbus_unit_sweep": _probe_modbus_unit_sweep}

# --------------------------------------------------------------------------
# Flask app
# --------------------------------------------------------------------------

def create_app(model: Model):
    from flask import Flask, jsonify, request, send_from_directory
    app = Flask(__name__, static_folder=str(ROOT / "static"), static_url_path="/static")
    state = {"model": model, "lock": threading.Lock()}

    @app.get("/")
    def index():
        return send_from_directory(str(ROOT / "static"), "index.html")

    @app.get("/api/graph")
    def graph():
        with state["lock"]:
            return jsonify(state["model"].to_graph())

    @app.get("/api/paths")
    def paths():
        with state["lock"]:
            m = state["model"]
            lbl = {a.id: a.label for a in m.assets.values()}
            zone = {a.id: a.zone(m.scope) for a in m.assets.values()}
            out = []
            for p in m.attack_paths():
                out.append({
                    "from": p["from"], "from_label": lbl.get(p["from"], p["from"]),
                    "to": p["to"], "to_label": lbl.get(p["to"], p["to"]),
                    "depth": p["depth"],
                    "hops": [{"from": h[0], "to": h[1], "proto": h[2],
                              "from_label": lbl.get(h[0], h[0]), "to_label": lbl.get(h[1], h[1])}
                             for h in p["hops"]],
                    "to_zone": zone.get(p["to"], "?"),
                })
            return jsonify({"paths": out})

    @app.get("/api/events")
    def events():
        with state["lock"]:
            return jsonify(state["model"].events[-200:])

    @app.post("/api/pcap")
    def import_pcap():
        data = request.get_json(force=True)
        paths = data.get("paths", [])
        n_total = 0
        with state["lock"]:
            for p in paths:
                if not Path(p).exists():
                    return jsonify({"error": f"not found: {p}"}), 400
                n_total += state["model"].ingest_pcap(p)
        return jsonify({"imported": n_total, "assets": len(state["model"].assets)})

    @app.post("/api/active/plan")
    def active_plan():
        data = request.get_json(force=True) if request.data else {}
        scope = state["model"].scope
        if data.get("scope"):
            scope = Scope(data["scope"])
        plan = ActivePlanner(scope).plan()
        return jsonify({"tasks": plan, "counts": {
            "allow": sum(1 for t in plan if t["decision"] == "allow"),
            "confirm": sum(1 for t in plan if t["decision"] == "confirm"),
            "block": sum(1 for t in plan if t["decision"] == "block")}})

    @app.post("/api/active/run")
    def active_run():
        data = request.get_json(force=True)
        execute = bool(data.get("execute"))
        assume_yes = bool(data.get("yes"))
        scope = state["model"].scope
        if data.get("scope"):
            scope = Scope(data["scope"])
            state["model"].scope = scope
            state["model"].recompute()
        plan = ActivePlanner(scope).plan()
        with state["lock"]:
            res = run_active(state["model"], plan, execute, assume_yes)
        return jsonify(res)

    @app.get("/api/export/<fmt>")
    def export(fmt):
        m = state["model"]
        if fmt == "json":
            return app.response_class(m.to_graph(), mimetype="application/json")
        if fmt == "dot":
            return app.response_class(m.to_dot(), mimetype="text/vnd.graphviz")
        if fmt == "svg":
            return _render_dot(m, "svg")
        if fmt == "png":
            return _render_dot(m, "png")
        if fmt == "csv":
            return app.response_class(m.assets_csv(), mimetype="text/csv")
        if fmt == "edges.csv":
            return app.response_class(m.edges_csv(), mimetype="text/csv")
        if fmt == "md":
            return app.response_class(m.report_md(), mimetype="text/markdown")
        return jsonify({"error": "unknown format"}), 400

    def _render_dot(m, fmt):
        import subprocess
        try:
            out = subprocess.run(["dot", f"-T{fmt}"], input=m.to_dot().encode(),
                                 capture_output=True, timeout=60)
            if out.returncode != 0:
                return jsonify({"error": out.stderr.decode()[:500]}), 500
            mime = "image/svg+xml" if fmt == "svg" else "image/png"
            return app.response_class(out.stdout, mimetype=mime)
        except FileNotFoundError:
            return jsonify({"error": "graphviz 'dot' not installed"}), 500

    return app

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def diff_models(old: Model, new: Model) -> dict:
    """Structural diff of two model states: new/departed assets, new edges,
    new findings. Asset identity = id (MAC, ip:, or virtual child ids)."""
    def a_dict(a, scope):
        d = a.to_dict(scope)
        d["zone"] = d["zone"]
        return d
    old_ids = set(old.assets)
    new_ids = set(new.assets)
    out = {
        "new_assets": [a_dict(new.assets[i], new.scope) for i in sorted(new_ids - old_ids)],
        "departed_assets": [a_dict(old.assets[i], old.scope) for i in sorted(old_ids - new_ids)],
        "new_edges": [],
        "new_findings": [],
    }
    old_edges = set(old.edges)
    lbl = lambda m, i: m.assets[i].label if i in m.assets else i
    for k in new.edges:
        if k not in old_edges:
            out["new_edges"].append({"source": k[0], "target": k[1], "proto": k[2],
                                     "source_label": lbl(new, k[0]),
                                     "target_label": lbl(new, k[1])})
    old_f = {f["id"] for f in old.findings}
    for f in new.findings:
        if f["id"] not in old_f:
            out["new_findings"].append({"id": f["id"], "severity": f["severity"], "title": f["title"]})
    return out


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="downstream", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest", help="passive ingest of pcap files")
    p.add_argument("pcaps", nargs="+")
    p.add_argument("--scope", default=None)
    p.add_argument("--db", default=str(ROOT / "data" / "state.json"))

    p = sub.add_parser("live", help="passive live capture on an interface")
    p.add_argument("--iface", required=True)
    p.add_argument("--scope", default=None)
    p.add_argument("--db", default=str(ROOT / "data" / "state.json"))
    p.add_argument("--duration", type=int, default=0, help="seconds; 0 = until Ctrl-C")
    p.add_argument("--snapshot", type=int, default=30, help="seconds between state snapshots (0 = off)")

    p = sub.add_parser("active", help="gated active discovery (dry-run by default)")
    p.add_argument("--scope", required=True)
    p.add_argument("--db", default=str(ROOT / "data" / "state.json"))
    p.add_argument("--plan-only", action="store_true")
    p.add_argument("--execute", action="store_true", help="actually send probes")
    p.add_argument("--yes", action="store_true", help="acknowledge 'confirm' decisions")

    p = sub.add_parser("crawl", help="iterative gated discovery: suggest or run next-layer probes")
    p.add_argument("--scope", required=True)
    p.add_argument("--db", default=str(ROOT / "data" / "state.json"))
    p.add_argument("--max-rounds", type=int, default=3)
    p.add_argument("--execute", action="store_true", help="actually send probes")
    p.add_argument("--yes", action="store_true", help="acknowledge 'confirm' decisions")

    p = sub.add_parser("diff", help="compare two saved states (new/departed devices, new edges)")
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--json", action="store_true", help="machine-readable output")

    p = sub.add_parser("export", help="export graph/assets from a saved state")
    p.add_argument("--db", default=str(ROOT / "data" / "state.json"))
    p.add_argument("--format", default="md", choices=["dot", "svg", "png", "csv", "edges.csv", "md", "json"])
    p.add_argument("-o", "--output", default=None)

    p = sub.add_parser("serve", help="launch the web UI")
    p.add_argument("--port", type=int, default=8756)
    p.add_argument("--db", default=str(ROOT / "data" / "state.json"))
    p.add_argument("--scope", default=None)

    args = ap.parse_args(argv)

    if args.cmd == "ingest":
        scope = Scope.load(args.scope) if args.scope else Scope()
        model = Model(scope)
        for pcap in args.pcaps:
            n = model.ingest_pcap(pcap)
            print(f"[+] {pcap}: {n} packets")
        model.save(args.db)
        print(f"[+] {len(model.assets)} assets, {len(model.edges)} conversations, {len(model.findings)} findings -> {args.db}")

    elif args.cmd == "live":
        from scapy.all import AsyncSniffer
        scope = Scope.load(args.scope) if args.scope else Scope()
        model = Model.load(args.db) if Path(args.db).exists() else Model(scope)
        model.scope = scope
        sniffer = AsyncSniffer(iface=args.iface, store=True)
        sniffer.start()
        print(f"[*] sniffing on {args.iface} (Ctrl-C to stop)" + (f" for {args.duration}s" if args.duration else ""))
        processed = 0
        try:
            t0 = time.time()
            next_snap = t0 + args.snapshot
            while True:
                time.sleep(1)
                now = time.time()
                if args.duration and now - t0 >= args.duration:
                    break
                if args.snapshot and now >= next_snap:
                    next_snap = now + args.snapshot
                    # fold fresh packets through the full two-pass pipeline so
                    # identity ordering + gateway materialization stay correct
                    fresh = sniffer.results[processed:] if sniffer.results else []
                    processed += len(fresh)
                    if fresh:
                        n = model.ingest_packets(fresh)
                        model.save(args.db)
                        print(f"[*] snapshot: +{len(fresh)} pkts -> {len(model.assets)} assets "
                              f"({len(model.findings)} findings)")
        except KeyboardInterrupt:
            pass
        pkts = sniffer.stop()
        remaining = sniffer.results[processed:] if sniffer.results else []
        if remaining:
            model.ingest_packets(remaining)
        model.save(args.db)
        print(f"[+] {processed + len(remaining)} packets -> {len(model.assets)} assets -> {args.db}")

    elif args.cmd == "active":
        scope = Scope.load(args.scope)
        model = Model.load(args.db) if Path(args.db).exists() else Model(scope)
        model.scope = scope
        planner = ActivePlanner(scope)
        plan = planner.plan()
        counts = {}
        for t in plan:
            counts[t["decision"]] = counts.get(t["decision"], 0) + 1
        print(f"[*] plan: {len(plan)} tasks {counts}")
        if args.plan_only or not args.execute:
            for t in plan[:20]:
                print(f"    {t['decision']:8s} {t['technique']:10s} {t.get('ip', '-')}")
            if len(plan) > 20:
                print(f"    ... {len(plan) - 20} more")
            print("[*] dry-run: nothing sent (pass --execute to run, --yes to accept confirm-gated probes)")
            return 0
        if not args.yes and any(t["decision"] == "confirm" for t in plan):
            print("[!] plan contains confirm-gated techniques; pass --yes to acknowledge")
            return 2
        res = run_active(model, plan, execute=True, assume_yes=args.yes)
        model.save(args.db)
        print(f"[*] sent={res['sent']} skipped={res['skipped']} blocked={res['blocked']} errors={res['errors']}")
        for f in res["findings"][:20]:
            print(f"    {f}")

    elif args.cmd == "crawl":
        scope = Scope.load(args.scope)
        db = Path(args.db)
        model = Model.load(db) if db.exists() else Model(scope)
        model.scope = scope
        for rnd in range(1, args.max_rounds + 1):
            targets = model.next_crawl_targets()
            if not targets:
                print(f"[*] round {rnd}: no further crawl targets — discovery saturated")
                break
            print(f"[*] round {rnd}: {len(targets)} crawl target(s)")
            for t in targets[:15]:
                print(f"    {t['ip']:18} {t['reason']}  (via {t['via']})")
            if len(targets) > 15:
                print(f"    ... {len(targets) - 15} more")
            if not args.execute:
                print("[*] dry-run: nothing sent (pass --execute to probe, --yes for confirm-gated)")
                break
            # execute: probe each target with the gated read-only techniques
            plan = []
            for t in targets:
                for tech in ("arp_ping", "tcp_probe", "modbus_id", "enip_list",
                             "mdns_query", "ssdp_msearch"):
                    plan.append({"technique": tech, "ip": t["ip"], "decision":
                                 scope.active_decision(tech)})
            res = run_active(model, plan, execute=True, assume_yes=args.yes)
            print(f"    -> sent={res['sent']} skipped={res['skipped']} blocked={res['blocked']}")
            if res["errors"]:
                for err in res["errors"][:5]:
                    print(f"    err: {err}")
            if res["sent"] == 0:
                break
        model.save(args.db)
        print(f"[+] {len(model.assets)} assets, {len(model.edges)} conversations -> {args.db}")

    elif args.cmd == "diff":
        old_m = Model.load(args.old)
        new_m = Model.load(args.new)
        d = diff_models(old_m, new_m)
        if args.json:
            print(json.dumps(d, indent=1))
        else:
            if d["new_assets"]:
                print("[+] NEW DEVICES:")
                for a in d["new_assets"]:
                    print(f"    {a['label']:24} {a['vendor'] or '?':24} {a['zone']:12} {','.join(a['roles'])}")
            if d["departed_assets"]:
                print("[-] DEPARTED (present before, absent now):")
                for a in d["departed_assets"]:
                    print(f"    {a['label']:24} {a['vendor'] or '?':24} {a['zone']:12}")
            if d["new_edges"]:
                print("[+] NEW CONVERSATIONS:")
                for e in d["new_edges"]:
                    print(f"    {e['source_label']} -> {e['target_label']} ({e['proto']})")
            if d["new_findings"]:
                print("[!] NEW FINDINGS:")
                for f in d["new_findings"]:
                    print(f"    [{f['severity'].upper()}] {f['title']}")
            if not (d["new_assets"] or d["departed_assets"] or d["new_edges"] or d["new_findings"]):
                print("[*] no differences")
        return 0

    elif args.cmd == "export":
        model = Model.load(args.db)
        if args.format == "dot":
            out = model.to_dot()
        elif args.format == "csv":
            out = model.assets_csv()
        elif args.format == "edges.csv":
            out = model.edges_csv()
        elif args.format == "md":
            out = model.report_md()
        elif args.format == "json":
            out = json.dumps(model.to_graph(), indent=1)
        else:
            import subprocess
            r = subprocess.run(["dot", f"-T{args.format}"], input=model.to_dot().encode(), capture_output=True)
            if r.returncode != 0:
                print(f"dot error: {r.stderr.decode()[:300]}", file=sys.stderr)
                return 1
            out = None
            dest = args.output or f"downstream_graph.{args.format}"
            Path(dest).write_bytes(r.stdout)
            print(f"[+] wrote {dest}")
            return 0
        if args.output:
            Path(args.output).write_text(out)
            print(f"[+] wrote {args.output}")
        else:
            print(out)

    elif args.cmd == "serve":
        db = Path(args.db)
        if db.exists():
            model = Model.load(db)
            if args.scope:
                model.scope = Scope.load(args.scope)
                model.recompute()
        else:
            scope = Scope.load(args.scope) if args.scope else Scope()
            model = Model(scope)
        app = create_app(model)
        print(f"[*] Downstream UI: http://127.0.0.1:{args.port}  (db: {db})")
        app.run(host="0.0.0.0", port=args.port, debug=False)

    return 0


if __name__ == "__main__":
    sys.exit(main())
