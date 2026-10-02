#!/usr/bin/env python3
"""gen_ot_pcap.py — synthetic known-answer OT network PCAP for Downstream.

Generates tests/fixtures/ot_plant.pcap: a small brewery process-control
network with known devices, protocols, and relationships. The expected
outcomes below are asserted by tests/test_passive.py; if you change this
fixture, change the tests (and this header) in the same commit.

  DOWNSTREAM TEST PLANT  (10.20.0.0/16)

  L1 control (10.20.5.0/24):
    10.20.5.11  00:0e:8c:aa:05:11  Siemens S7-1200 PLC "TANK_FARM_A"   (S7 slave,  tcp/102)
    10.20.5.12  00:80:f4:aa:05:12  Schneider Modicon PLC                (Modbus slave, tcp/502; emits exceptions)
    10.20.5.13  00:1d:9c:aa:05:13  Allen-Bradley ControlLogix          (ENIP slave, tcp/44818)
    10.20.5.14  00:0b:ab:aa:05:14  Advantech RTU                       (DNP3 outstation, tcp/20000)
    10.20.5.15  00:1b:1b:aa:05:15  BACnet building controller           (UDP/47808 who-is)
    10.20.5.16  00:0b:ab:aa:05:16  BACnet field device                  (UDP/47808 i-am)
    10.20.5.88  00:1e:c2:aa:05:88  CONTRACTOR-LT (Apple laptop)         (unmanaged L1 device, Modbus master!)
    L2-only:     00:0e:8c:bb:00:01  PROFINET IO device "rtls-pn-01"     (PN-DCP identify response, no IP)

  L2/L3 SCADA (10.20.7.0/24):
    10.20.7.20  00:0c:29:aa:07:20  SCADA-SRV (VMware)                   (modbus/s7/enip master, opc-ua client, dnp3 master)
    10.20.7.21  00:23:7d:aa:07:21  HIST-01 (HP)                         (OPC UA server, tcp/4840)
    10.20.7.1   00:90:e8:aa:07:01  gateway/router (MOXA)                (LLDP router caps, ARP)

  Enterprise (10.20.9.0/24):
    10.20.9.30  00:23:7d:aa:09:30  ENG-WS (HP engineering workstation)  (S7 master -> PLC; L4->L1 direct path)

  Switch: 10.20.5.2 00:90:e8:aa:05:02  SW-CTRL-01 (LLDP bridge caps, sysname, mgmt addr)

EXPECTED ASSERTIONS (tests/test_passive.py):
  assets: >= 12 assets with IP + 1 MAC-only PROFINET asset
  vendor: .11/.16? no — .11 Siemens (OUI 00:0e:8c), .12 Telemecanique, .13 Rockwell,
          .88 Apple, .20 VMware, .21/.30 Hewlett Packard, switch Moxa
  hostnames: SCADA-SRV + HIST-01 + ENG-WS (NBNS), CONTRACTOR-LT (NBNS), SW-CTRL-01 (LLDP sysname),
             rtls-pn-01 (PN-DCP name-of-station)
  roles:    .11 plc (s7 slave), .12 plc (modbus slave), .13 plc (enip slave), .14 rtu (dnp3 outstation),
            .20 scada_server (multi-protocol master + opcua client), .21 historian (opcua server),
            switch -> switch (LLDP bridge), gateway -> gateway (LLDP router), .88 unclassified
  edges:    (.20 ->.12 modbus) (.20 ->.11 s7comm) (.20 ->.13 enip) (.20 ->.21 opcua)
            (.20 ->.14 dnp3) (.15 ->.16 bacnet) (.30 ->.11 s7comm) (.88 ->.12 modbus)
  modbus:   exception frames counted on .12; write FC6 observed from .20 (write_activity finding)
  findings: unmanaged_l1_device (.88), ot_master_unmanaged (.88 modbus master),
            enterprise_to_l1 (.30 -> .11 s7comm), write_activity (.20 -> .12 FC6)
"""
import struct
import sys
from pathlib import Path

from scapy.all import Ether, IP, ARP, UDP, TCP, Raw, wrpcap, conf

conf.verb = 0

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "ot_plant.pcap"

# --- device table ----------------------------------------------------------- #
MAC = {
    "plc_s7":  "00:0e:8c:aa:05:11",
    "plc_mb":  "00:80:f4:aa:05:12",
    "plc_ab":  "00:1d:9c:aa:05:13",
    "rtu":     "00:0b:ab:aa:05:14",
    "bac_ctrl":"00:1b:1b:aa:05:15",
    "bac_dev": "00:0b:ab:aa:05:16",
    "laptop":  "00:1e:c2:aa:05:88",
    "scada":   "00:0c:29:aa:07:20",
    "hist":    "00:23:7d:aa:07:21",
    "gw":      "00:90:e8:aa:07:01",
    "ews":     "00:23:7d:aa:09:30",
    "sw":      "00:90:e8:aa:05:02",
    "pn_dev":  "00:0e:8c:bb:00:01",
}

pkts = []
def eth_ip_tcp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload, seq=1, ttl=64):
    p = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip, ttl=ttl)
    p = p / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=1)
    return p / Raw(load=payload)

def eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload):
    return (Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) /
            UDP(sport=sport, dport=dport) / Raw(load=payload))

# --- Modbus TCP ------------------------------------------------------------- #
def mbap(txid, unit, fc, data=b""):
    return struct.pack(">HHHB", txid, 0, 2 + 1 + 1 + len(data), unit) + bytes([fc]) + data

def modbus_flow(client, server, n=3, with_write=False, with_exc=False, unit=1):
    """FC3 reads client->server, responses server->client."""
    sp = 40000
    out = []
    for i in range(n):
        req = mbap(i + 1, unit, 3, struct.pack(">HH", 100, 8))       # read holding regs
        resp = mbap(i + 1, unit, 3, bytes([16]) + b"\x11" * 16)
        out.append(eth_ip_tcp(MAC[client], MAC[server], IPS[client], IPS[server], sp + i, 502, req))
        out.append(eth_ip_tcp(MAC[server], MAC[client], IPS[server], IPS[client], 502, sp + i, resp))
    if with_write:
        req = mbap(90, unit, 6, struct.pack(">HH", 200, 1234))       # write single register
        out.append(eth_ip_tcp(MAC[client], MAC[server], IPS[client], IPS[server], 40010, 502, req))
        resp = mbap(90, unit, 6, struct.pack(">HH", 200, 1234))
        out.append(eth_ip_tcp(MAC[server], MAC[client], IPS[server], IPS[client], 502, 40010, resp))
    if with_exc:
        req = mbap(91, unit, 2, struct.pack(">HH", 0, 2))            # illegal read of discrete inputs
        out.append(eth_ip_tcp(MAC[client], MAC[server], IPS[client], IPS[server], 40011, 502, req))
        resp = mbap(91, unit, 0x82, bytes([2]))                      # exception: ILLEGAL DATA ADDRESS
        out.append(eth_ip_tcp(MAC[server], MAC[client], IPS[server], IPS[client], 502, 40011, resp))
    return out

# --- S7comm (TPKT/COTP/S7) -------------------------------------------------- #
def tpkt_cotp_s7(s7_pdu):
    cotp = bytes([0x02, 0xF0, 0x80])                                 # DT data, EOT
    tpdu = cotp + s7_pdu
    return struct.pack(">BH", 3, len(tpdu) + 4) + tpdu

def s7_read(job, db, count=4):
    param = bytes([0x12, 0x0A, 0x10, 0x00]) + struct.pack(">H", count)
    param += struct.pack(">H", db) + bytes([0x84]) + b"\x00\x00\x08"  # area DB, word offset 1
    hdr = struct.pack(">BBHHHHH", 0x32, 1, 1, 0, job, len(param), 0) # rosctr=1 job
    return hdr + param

def s7_ack_data(job, param_len, data="ok"):
    d = data.encode() if isinstance(data, str) else data
    # protocol-id, rosctr=2 (ack-data), red-id, pdu-ref, param-len, data-len, error
    hdr = struct.pack(">BBHHHHH", 0x32, 2, 0, job, 0, len(d), 0)
    item = bytes([0xFF, 0x04, 0x00, 0x40]) + bytes([len(d)]) + d
    return hdr + item

def s7_setup(job=1):
    param = bytes([0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
                   0x03, 0xC0, 0x00, 0x01])                          # pdu len 480
    hdr = struct.pack(">BBHHHHH", 0x32, 1, 1, 0, job, len(param), 0)
    return hdr + param

def s7_flow(client, server, n=2):
    out = []
    for i in range(n):
        out.append(eth_ip_tcp(MAC[client], MAC[server], IPS[client], IPS[server],
                              41000 + i, 102, tpkt_cotp_s7(s7_read(100 + i, 10))))
        out.append(eth_ip_tcp(MAC[server], MAC[client], IPS[server], IPS[client],
                              102, 41000 + i, tpkt_cotp_s7(s7_ack_data(100 + i, 0))))
    return out

# --- EtherNet/IP ------------------------------------------------------------ #
def enip(cmd, body=b"", session=0):
    # 24-byte ENIP header: cmd(2) len(2) session(4) status(4) ctx(8) options(4)
    return struct.pack("<HHII8sI", cmd, len(body), session, 0, b"ctx-dstr", 0) + body

def enip_list_identity_resp_body(product=b"1756-L83E", vendor=1):
    sockaddr = struct.pack(">HH4s8s", 2, 0xAF12, bytes([10, 20, 5, 13]), b"\x00" * 8)
    ident = struct.pack("<HHHBB", vendor, 0x0C, 87, 35, 1)           # type, code, rev major.minor
    ident += struct.pack("<H", 0x360)                                # status
    ident += struct.pack("<I", 0xA1B2C3D4)                           # serial
    ident += bytes([len(product)]) + product + bytes([0x04])         # product name, state
    item2 = struct.pack("<HH", 0x000C, len(sockaddr + ident)) + sockaddr + ident
    return struct.pack("<H", 1) + item2                              # item count, null-addr wrapped
    # NOTE: downstream parses defensively; fixture layout = count(2) + item(type,len,sockaddr,identity)

def enip_flow(client, server):
    out = []
    out.append(eth_ip_tcp(MAC[client], MAC[server], IPS[client], IPS[server], 42000, 44818,
                          enip(0x63)))                                # listIdentity req
    out.append(eth_ip_tcp(MAC[server], MAC[client], IPS[server], IPS[client], 44818, 42000,
                          enip(0x63, enip_list_identity_resp_body(), session=0x1122)))
    out.append(eth_ip_tcp(MAC[client], MAC[server], IPS[client], IPS[server], 42001, 44818,
                          enip(0x65, struct.pack("<I", 0x01000000)))) # register session
    return out

# --- DNP3 ------------------------------------------------------------------- #
def crc16_dnp(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return crc & 0xFFFF

def dnp3_link(dst, src, app_fir_fin=True, app=b"", ctrl_extra=0x44):
    body = bytes([ctrl_extra]) + struct.pack("<HH", dst, src) + app
    ln = len(body)
    hdr_crc = crc16_dnp(bytes([0x05, 0x64, ln])[:3])
    frame = bytes([0x05, 0x64, ln]) + body
    return frame + struct.pack("<H", crc16_dnp(body))

def dnp3_read(seq):
    app_ctrl = 0xC0 | (seq & 0x0F)                                   # FIR|FIN|UNS, request
    return bytes([app_ctrl, 0x01]) + struct.pack(">HHBB", 30, 0x0102, 7, 0)  # FC1 read, g30 v2 q8

def dnp3_flow(master, outstation, n=2):
    out = []
    for i in range(n):
        out.append(eth_ip_tcp(MAC[master], MAC[outstation], IPS[master], IPS[outstation],
                              43000 + i, 20000, dnp3_link(4, 3, app=dnp3_read(i))))
        out.append(eth_ip_tcp(MAC[outstation], MAC[master], IPS[outstation], IPS[master],
                              20000, 43000 + i, dnp3_link(3, 4, app=bytes([0xC0 | i, 0x81]) + b"\x02\x00")))
    return out

def dnp3_link_flow(master, concentrator, own_link=3, remote_link=7):
    """Master polls the concentrator's own link, then a forwarded outstation."""
    out = []
    out.append(eth_ip_tcp(MAC[master], MAC[concentrator], IPS[master], IPS[concentrator],
                          43100, 20000, dnp3_link(own_link, 4, app=dnp3_read(0))))
    out.append(eth_ip_tcp(MAC[concentrator], MAC[master], IPS[concentrator], IPS[master],
                          20000, 43100, dnp3_link(4, own_link, app=bytes([0xC0, 0x81]) + b"\x02\x00")))
    out.append(eth_ip_tcp(MAC[master], MAC[concentrator], IPS[master], IPS[concentrator],
                          43101, 20000, dnp3_link(remote_link, 4, app=dnp3_read(1))))
    out.append(eth_ip_tcp(MAC[concentrator], MAC[master], IPS[concentrator], IPS[master],
                          20000, 43101, dnp3_link(4, remote_link, app=bytes([0xC1, 0x81]) + b"\x03\x00")))
    return out

def s7_flow_routed(client, server, via="gw", n=1):
    """S7 conversation where the server is behind a router: TTL shows 1 hop."""
    out = []
    for i in range(n):
        out.append(eth_ip_tcp(MAC[client], MAC[via], IPS[client], IPS[server],
                              45000 + i, 102, tpkt_cotp_s7(s7_read(200 + i, 30)), ttl=63))
        out.append(eth_ip_tcp(MAC[via], MAC[client], IPS[server], IPS[client],
                              102, 45000 + i, tpkt_cotp_s7(s7_ack_data(200 + i, 0)), ttl=63))
    return out

# --- BACnet ----------------------------------------------------------------- #
def bacnet_whois():
    # BVLC original-broadcast(4) + NPDU(2) + APDU unconfirmed-req who-is(2) = 8
    bvlc = bytes([0x81, 0x0B]) + struct.pack(">H", 8)
    npdu = bytes([0x01, 0x00])
    apdu = bytes([0x10, 0x08])                                       # unconfirmed req, who-is, no limits
    return bvlc + npdu + apdu

def bacnet_iam(instance=101, vendor=85):
    objid = struct.pack(">I", (8 << 22) | instance)                  # device object type 8, 22-bit instance
    apdu = bytes([0x10, 0x00])                                       # unconfirmed req, i-am
    apdu += bytes([0x0C]) + objid                                    # ctx tag0, objid, len 4
    apdu += bytes([0x19, 0x00])                                      # ctx tag1, max-apdu (1B)
    apdu += bytes([0x29, 0x00])                                      # ctx tag2, segmentation: none
    apdu += bytes([0x3A]) + struct.pack(">H", vendor)                # ctx tag3, vendor id, len 2
    npdu = bytes([0x01, 0x00])
    total = 4 + len(npdu) + len(apdu)
    return bytes([0x81, 0x0B]) + struct.pack(">H", total) + npdu + apdu

# --- OPC UA ----------------------------------------------------------------- #
def opcua_hello(url="opc.tcp://10.20.7.21:4840"):
    # HEL: msg-type(4) chunk-type(1) size(4) scid(4) proto-ver(4) recv(4) send(4)
    #      max-msg(4) max-chunk(4) url-len(4) url-bytes
    tail = struct.pack("<IIIII", 0, 8192, 16384, 8192, 8192)
    tail += struct.pack("<I", len(url)) + url.encode()
    size = 8 + 4 + len(tail)
    return b"HELF" + b"F" + struct.pack("<I", size) + tail

def opcua_open_channel():
    # OPN: msg-type(4) chunk(1) size(4) scid(4) then security policy uri "open"
    pol = struct.pack("<iI", 0, len(b"http://opcfoundation.org/UA/SecurityPolicy#None")) + b"http://opcfoundation.org/UA/SecurityPolicy#None"
    body = struct.pack("<I", 0) + pol + b"\x00" * 32
    size = 8 + 4 + len(body)
    return b"OPNF" + b"F" + struct.pack("<I", size) + struct.pack("<I", 0) + body

def opcua_flow(client, server):
    return [
        eth_ip_tcp(MAC[client], MAC[server], IPS[client], IPS[server], 44000, 4840, opcua_hello()),
        eth_ip_tcp(MAC[server], MAC[client], IPS[server], IPS[client], 4840, 44000, opcua_open_channel()),
    ]

# --- LLDP ------------------------------------------------------------------- #
def lldp_tlv(t, val):
    return struct.pack(">H", (t << 9) | len(val)) + val

def lldp_frame(sysname, caps_word=0x0004):                           # default: bridge only
    body = lldp_tlv(1, b"\x04" + bytes.fromhex("000102"))            # chassis id (locally assigned)
    body += lldp_tlv(2, b"\x04" + b"eth0")
    body += lldp_tlv(3, struct.pack(">H", 120))
    body += lldp_tlv(4, b"Port 5 - uplink to SCADA")
    body += lldp_tlv(5, sysname.encode())
    body += lldp_tlv(7, struct.pack(">HH", caps_word, caps_word))    # system capabilities + enabled
    body += lldp_tlv(8, bytes([5, 1]) + bytes([10, 20, 5, 2]) + b"\x00" + struct.pack(">I", 0))  # mgmt addr 10.20.5.2
    body += lldp_tlv(0, b"")
    return Ether(src=MAC["sw"], dst="01:80:c2:00:00:0e", type=0x88CC) / Raw(load=body)

def lldp_router_frame():
    body = lldp_tlv(1, b"\x04" + bytes.fromhex("000201"))
    body += lldp_tlv(2, b"\x04" + b"wan0")
    body += lldp_tlv(3, struct.pack(">H", 120))
    body += lldp_tlv(5, b"GW-CTRL-01")
    body += lldp_tlv(7, struct.pack(">HH", 0x0014, 0x0014))          # router + bridge
    body += lldp_tlv(8, bytes([5, 1]) + bytes([10, 20, 7, 1]) + b"\x00" + struct.pack(">I", 0))  # mgmt addr 10.20.7.1
    body += lldp_tlv(0, b"")
    return Ether(src=MAC["gw"], dst="01:80:c2:00:00:0e", type=0x88CC) / Raw(load=body)

# --- PROFINET DCP ----------------------------------------------------------- #
def dcp_block(opt, sub, val):
    return bytes([opt, sub]) + struct.pack(">H", len(val)) + val

def pn_dcp_identify_response(station="rtls-pn-01"):
    svc = dcp_block(0x03, 0x02, station.encode())                    # name of station
    svc += dcp_block(0x03, 0x05, bytes([0x01]))                      # device role: IO device
    svc += dcp_block(0x02, 0x01, bytes([10, 20, 5, 17]) + b"\xff\xff\xff\x00" + b"\x00" * 6)
    hdr = bytes([0x05, 0x01]) + struct.pack(">I", 0x00000001) + b"\x00\x00" + struct.pack(">H", len(svc))
    frame_id = 0x0E5D                                                # DCP identify response
    pn_hdr = struct.pack(">H", frame_id) + b"\x00\x00"
    return Ether(src=MAC["pn_dev"], dst="01:0e:cf:00:00:00", type=0x8892) / Raw(load=pn_hdr + hdr + svc)

def pn_rt_data(src_key="scada", dst_key="plc_s7"):
    frame_id = 0x8000 | 0x0100                                       # RT data, low prio
    return (Ether(src=MAC[src_key], dst=MAC[dst_key], type=0x8892) /
            Raw(load=struct.pack(">H", frame_id) + b"\x00" * 2 + b"\xc0\x00\x01\x02"))

# --- NBNS / DHCP ------------------------------------------------------------ #
def nbns_name(name):
    name15 = (name + " " * 15)[:15]
    enc = "".join(chr(ord("A") + (ord(c) >> 4)) + chr(ord("A") + (ord(c) & 0xF)) for c in name15)
    return enc.encode() + enc[:2]  # placeholder, fixed below

def nbns_name_fixed(name, suffix=0x00):
    name15 = (name + " " * 15)[:15]
    enc = "".join(chr(ord("A") + (ord(c) >> 4)) + chr(ord("A") + (ord(c) & 0xF)) for c in name15 + chr(suffix))
    return enc.encode()

def nbns_registration(host, ip_src, suffix=0x00):
    hdr = struct.pack(">HHHHHH", 0x1C40, 0x2910, 1, 0, 0, 0)        # registration, rd=1
    q = nbns_name_fixed(host, suffix) + b"\x00" + struct.pack(">HH", 0x20, 1)
    return hdr + q                                                  # QD alone carries the name

def nbns_query(host):
    hdr = struct.pack(">HHHHHH", 0x0110, 0x0100, 1, 0, 0, 0)
    q = nbns_name_fixed(host) + b"\x00" + struct.pack(">HH", 0x20, 1)
    return hdr + q

def dhcp_discover(hostname):
    msg = (b"\x01" + bytes([1, 6, 0]) + b"\x78\x56\x34\x12" +        # op/htype/hlen/hops + xid
           b"\x00\x00\x00\x00" +                                     # secs, flags
           b"\x00\x00\x00\x00" * 3 +                                 # ci/yi/gi addr
           b"\x00\x1e\xc2\xaa\x05\x88" + b"\x00" * 10 +              # chaddr
           b"\x00" * 64 + b"\x00" * 128)                             # sname + file => 236-byte header
    opt53 = bytes([53, 1, 1])                                        # DHCPDISCOVER
    opt12 = bytes([12, len(hostname)]) + hostname.encode()
    opt55 = bytes([55, 2, 1, 15])
    return msg + b"\x63\x82\x53\x63" + opt53 + opt12 + opt55 + b"\xff"

# --- ARP -------------------------------------------------------------------- #
def arp_whohas(target_ip, src_key):
    """Who-has from src_key: psrc/hwsrc must be the SENDER's own identity."""
    return Ether(src=MAC[src_key], dst="ff:ff:ff:ff:ff:ff", type=0x0806) / ARP(
        op=1, hwsrc=MAC[src_key], psrc=IPS[src_key], hwdst="00:00:00:00:00:00", pdst=target_ip)

# ============================================================================
IPS = {
    "plc_s7": "10.20.5.11", "plc_mb": "10.20.5.12", "plc_ab": "10.20.5.13",
    "rtu": "10.20.5.14", "bac_ctrl": "10.20.5.15", "bac_dev": "10.20.5.16",
    "laptop": "10.20.5.88", "scada": "10.20.7.20", "hist": "10.20.7.21",
    "gw": "10.20.7.1", "ews": "10.20.9.30", "sw": "10.20.5.2",
    "mb_gw": "10.20.5.30", "remote_plc": "10.20.5.31", "dnpc": "10.20.5.32",
}

MAC["mb_gw"] = "00:90:e8:aa:05:30"     # MOXA Modbus/TCP gateway
MAC["remote_plc"] = "00:0e:8c:aa:05:31"  # Siemens S7-300 slave behind gw
MAC["dnpc"] = "00:0b:ab:aa:05:32"      # Advantech DNP3 data concentrator

def build():
    out = []
    # control-plane conversations
    out += modbus_flow("scada", "plc_mb", n=3, with_write=True, with_exc=True)
    out += modbus_flow("laptop", "plc_mb", n=1)
    out += s7_flow("scada", "plc_s7")
    out += s7_flow("ews", "plc_s7", n=1)
    out += enip_flow("scada", "plc_ab")
    out += dnp3_flow("scada", "rtu")
    out += opcua_flow("scada", "hist")

    # --- layer crawl scenarios ---
    # A) Modbus/TCP gateway: SCADA polls TWO unit IDs (17, 18) through one box
    out += modbus_flow("scada", "mb_gw", n=2, unit=17)
    out += modbus_flow("scada", "mb_gw", n=1, unit=18)
    # B) DNP3 data concentrator: SCADA polls link 3 (own) then remote link 7
    out += dnp3_link_flow("scada", "dnpc", own_link=3, remote_link=7)
    # C) routed remote PLC: S7 through the MOXA router (TTL decremented)
    out += s7_flow_routed("scada", "remote_plc", via="gw")

    # BACnet
    out.append(eth_ip_udp(MAC["bac_ctrl"], "ff:ff:ff:ff:ff:ff", IPS["bac_ctrl"],
                          "10.20.5.255", 47808, 47808, bacnet_whois()))
    out.append(eth_ip_udp(MAC["bac_dev"], "ff:ff:ff:ff:ff:ff", IPS["bac_dev"],
                          "10.20.5.255", 47808, 47808, bacnet_iam(instance=101, vendor=85)))
    out.append(eth_ip_udp(MAC["bac_ctrl"], MAC["bac_dev"], IPS["bac_ctrl"],
                          IPS["bac_dev"], 47808, 47808, bacnet_iam(instance=102, vendor=85)))

    # discovery / infrastructure
    out.append(lldp_frame("SW-CTRL-01", caps_word=0x0004))
    out.append(lldp_router_frame())
    out.append(pn_dcp_identify_response())
    out.append(pn_rt_data("scada", "plc_s7"))
    out.append(pn_rt_data("scada", "plc_ab"))

    # identity broadcasts
    out.append(eth_ip_udp(MAC["scada"], "ff:ff:ff:ff:ff:ff", IPS["scada"], "10.20.7.255",
                          137, 137, nbns_registration("SCADA-SRV", IPS["scada"])))
    out.append(eth_ip_udp(MAC["hist"], "ff:ff:ff:ff:ff:ff", IPS["hist"], "10.20.7.255",
                          137, 137, nbns_registration("HIST-01", IPS["hist"])))
    out.append(eth_ip_udp(MAC["ews"], "ff:ff:ff:ff:ff:ff", IPS["ews"], "10.20.9.255",
                          137, 137, nbns_registration("ENG-WS", IPS["ews"])))
    out.append(eth_ip_udp(MAC["laptop"], "ff:ff:ff:ff:ff:ff", IPS["laptop"], "10.20.5.255",
                          137, 137, nbns_query("CONTRACTOR-LT")))
    out.append(eth_ip_udp(MAC["laptop"], "ff:ff:ff:ff:ff:ff", IPS["laptop"], "255.255.255.255",
                          68, 67, dhcp_discover("CONTRACTOR-LT")))

    # ARP binding evidence
    out.append(arp_whohas(IPS["plc_mb"], src_key="scada"))
    out.append(arp_whohas(IPS["laptop"], src_key="gw"))

    return out

if __name__ == "__main__":
    packets = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUT), packets)
    print(f"wrote {len(packets)} packets -> {OUT}")
    sys.exit(0)
