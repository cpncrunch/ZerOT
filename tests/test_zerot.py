"""ZerOT tests: fixture-driven passive pipeline, roles, findings, zones, exports, gating."""
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import zerot as ds
from zerot import Model, Scope

FIXTURE = ROOT / "tests" / "fixtures" / "ot_plant.pcap"

SCOPE = {
    "name": "ZerOT test plant",
    "zones": {"L1": ["10.20.5.0/24"], "L2_L3": ["10.20.7.0/24"], "Enterprise": ["10.20.9.0/24"]},
    "excluded": [],
    "active": {"enabled": True, "techniques": {"arp_ping": "allow", "tcp_probe": "confirm",
                                               "modbus_id": "confirm", "enip_list": "allow"}},
}


@pytest.fixture(scope="module")
def model():
    m = Model(Scope(SCOPE))
    n = m.ingest_pcap(FIXTURE)
    assert n > 30, f"expected >30 parsed packets, got {n}"
    return m


def by_ip(model):
    return {ip: a for a in model.assets.values() for ip in a.ips}


# ---- assets --------------------------------------------------------------- #

def test_asset_count(model):
    assert len(model.assets) >= 12          # 12 IP assets + 1 MAC-only PROFINET device


def test_mac_ip_merge(model):
    a = model.assets.get("00:0E:8C:AA:05:11")
    assert a is not None, "PLC S7 must be MAC-keyed"
    assert "10.20.5.11" in a.ips
    assert a.vendor == "Siemens AG"
    scada = [x for x in model.assets.values() if "10.20.7.20" in x.ips]
    assert len(scada) == 1
    assert scada[0].vendor == "VMware, Inc."


def test_mac_only_profinet_asset(model):
    pn = model.assets.get("00:0E:8C:BB:00:01")
    assert pn is not None, "MAC-only PROFINET asset must exist"
    assert "rtls-pn-01" in pn.hostnames
    assert "pn_io_device" in pn.roles
    assert "10.20.5.17" in pn.ips      # IP learned from DCP identify, no IP-layer traffic seen


def test_vendors(model):
    m = by_ip(model)
    assert m["10.20.5.12"].vendor == "TELEMECANIQUE ELECTRIQUE"
    assert m["10.20.5.13"].vendor == "Rockwell Automation"
    assert m["10.20.5.88"].vendor == "Apple, Inc."
    assert m["10.20.5.2"].vendor.startswith("MOXA")
    assert m["10.20.7.21"].vendor == "Hewlett Packard"


def test_hostnames(model):
    names = set()
    for a in model.assets.values():
        names |= a.hostnames
    assert {"SCADA-SRV", "HIST-01", "ENG-WS", "CONTRACTOR-LT", "SW-CTRL-01", "rtls-pn-01"} <= names


def test_enip_product(model):
    ab = model.assets.get("00:1D:9C:AA:05:13")
    assert ab is not None
    assert ab.attrs.get("enip_product") == "1756-L83E"


def test_dnp3_link_addresses(model):
    rtu = model.assets.get("00:0B:AB:AA:05:14")
    assert rtu is not None
    assert rtu.attrs.get("dnp3_link_addr") in (3, 4)


def test_iec104_rtu_and_conversation(model):
    rtu = model.assets.get("74:F6:61:AA:05:33")
    assert rtu is not None
    assert "iec104_slave" in rtu.roles
    assert "rtu" in rtu.roles                      # role inference promotes it
    assert rtu.vendor == "Schneider Electric Fire & Security Oy"
    assert rtu.attrs.get("iec104_casdu") == 1
    scada = by_ip(model)["10.20.7.20"]
    assert (scada.id, rtu.id, "iec104") in model.edges
    e = model.edges[(scada.id, rtu.id, "iec104")]
    assert e.count >= 2 and e.writes == 0          # interrogation only, no commands
    # scada is also master over iec104
    assert "master" in scada.roles


def test_bacnet_instance(model):
    m = by_ip(model)
    assert m["10.20.5.15"].attrs.get("bacnet_instance") == 102
    assert m["10.20.5.16"].attrs.get("bacnet_instance") == 101


def test_zones(model):
    m = by_ip(model)
    assert m["10.20.5.11"].zone(model.scope) == "L1"
    assert m["10.20.7.20"].zone(model.scope) == "L2_L3"
    assert m["10.20.9.30"].zone(model.scope) == "Enterprise"


def test_roles(model):
    m = by_ip(model)
    assert "plc" in m["10.20.5.11"].roles
    assert "plc" in m["10.20.5.12"].roles
    assert "plc" in m["10.20.5.13"].roles
    assert "rtu" in m["10.20.5.14"].roles
    assert "scada_server" in m["10.20.7.20"].roles
    assert "engineering_ws" in m["10.20.9.30"].roles
    assert "switch" in m["10.20.5.2"].roles
    assert "gateway" in m["10.20.7.1"].roles
    assert "building_controller" in m["10.20.5.15"].roles
    # routed remote PLC: its own asset, distinct from the router it hides behind.
    # Behind a router its MAC/vendor are NOT visible on this segment; TTL + the
    # last-hop-router attr are the evidence of the extra layer.
    assert "plc" in m["10.20.5.31"].roles
    assert m["10.20.5.31"].mac == ""
    assert m["10.20.5.31"].attrs.get("last_hop_router") == "00:90:E8:AA:07:01"
    assert m["10.20.5.31"].attrs.get("inferred_hops") == 1


def test_master_roles_directionality(model):
    m = by_ip(model)
    assert "master" in m["10.20.7.20"].roles
    assert "master" in m["10.20.9.30"].roles
    assert "master" in m["10.20.5.88"].roles        # contractor laptop = rogue master
    assert "master" not in m["10.20.5.11"].roles
    assert "master" not in m["10.20.5.12"].roles


def test_edges(model):
    ids = {ip: a.id for a in model.assets.values() for ip in a.ips}
    E = {(e.src, e.dst, e.proto) for e in model.edges.values()}
    assert (ids["10.20.7.20"], ids["10.20.5.12"], "modbus") in E
    assert (ids["10.20.7.20"], ids["10.20.5.11"], "s7comm") in E
    assert (ids["10.20.7.20"], ids["10.20.5.13"], "enip") in E
    assert (ids["10.20.7.20"], ids["10.20.5.14"], "dnp3") in E
    assert (ids["10.20.7.20"], ids["10.20.7.21"], "opcua") in E
    assert (ids["10.20.9.30"], ids["10.20.5.11"], "s7comm") in E
    assert (ids["10.20.5.88"], ids["10.20.5.12"], "modbus") in E
    assert (ids["10.20.5.15"], ids["10.20.5.16"], "bacnet") in E


def test_writes_and_exceptions(model):
    ids = {ip: a.id for a in model.assets.values() for ip in a.ips}
    e = model.edges[(ids["10.20.7.20"], ids["10.20.5.12"], "modbus")]
    assert e.writes == 1            # write REQUESTS only (FC6 request counted once)
    assert e.exceptions == 1


def test_findings(model):
    f88 = [f for f in model.findings if "00:1E:C2:AA:05:88" in f["assets"]]
    assert f88, "contractor laptop must produce an unmanaged finding"
    assert f88[0]["severity"] == "high"
    assert any(f["id"].startswith("ent2ctl-") for f in model.findings)
    assert any(f["id"].startswith("writes-") for f in model.findings)


# ---- layer crawl: gateways, concentrators, routed layers --------------------- #

def test_modbus_gateway_virtual_children(model):
    # 10.20.5.30 polled at unit 17 AND 18 -> gateway with two child PLCs
    gw = [a for a in model.assets.values() if "10.20.5.30" in a.ips][0]
    assert "modbus_gateway" in gw.roles
    kids = [a for a in model.assets.values() if a.attrs.get("behind_gateway") == gw.id]
    assert len(kids) == 2
    assert {k.attrs.get("modbus_unit") for k in kids} == {17, 18}
    assert all("plc" in k.roles for k in kids)
    # SCADA reaches each child through the gateway (direct + bridge edges)
    scada = [a for a in model.assets.values() if "10.20.7.20" in a.ips][0]
    for k in kids:
        assert (scada.id, k.id, "modbus") in model.edges
        assert (gw.id, k.id, "modbus_bridge") in model.edges


def test_no_ghost_children_for_direct_plc(model):
    # 10.20.5.12 polled at a single unit -> it is just a PLC, no children
    plc = [a for a in model.assets.values() if "10.20.5.12" in a.ips][0]
    assert "modbus_gateway" not in plc.roles
    assert not [a for a in model.assets.values() if a.attrs.get("behind_gateway") == plc.id]


def test_dnp3_concentrator_children(model):
    dc = [a for a in model.assets.values() if "10.20.5.32" in a.ips][0]
    assert "dnp3_concentrator" in dc.roles
    kids = [a for a in model.assets.values() if a.attrs.get("behind_gateway") == dc.id]
    assert len(kids) == 1
    assert kids[0].attrs.get("dnp3_link_addr") == 7
    assert "rtu" in kids[0].roles


def test_router_guard_routed_s7(model):
    # remote PLC behind the MOXA router keeps its own identity
    m = by_ip(model)
    assert "10.20.5.31" in m
    rtr = m["10.20.7.1"]
    assert "10.20.5.31" not in rtr.ips
    assert m["10.20.5.31"].attrs.get("last_hop_router") == rtr.mac
    assert m["10.20.5.31"].attrs.get("inferred_hops") == 1
    # routed conversation edge exists (master -> remote plc over s7comm)
    ews_ids = {ip: a.id for a in model.assets.values() for ip in a.ips}
    assert (ews_ids["10.20.7.20"], ews_ids["10.20.5.31"], "s7comm") in model.edges


def test_attack_paths_traverse_layers(model):
    paths = model.attack_paths()
    assert paths, "enterprise master must reach PLC/RTU targets"
    # ENG-WS reaches the gateway-hidden child PLC within 3 hops (through the
    # SCADA server and the gateway/bridge layer)
    gw = [a for a in model.assets.values() if "10.20.5.30" in a.ips][0]
    child = [a for a in model.assets.values()
             if a.attrs.get("behind_gateway") == gw.id and a.attrs.get("modbus_unit") == 17][0]
    ews = [a for a in model.assets.values() if "10.20.9.30" in a.ips][0]
    hit = [p for p in paths if p["from"] == ews.id and p["to"] == child.id]
    assert hit and hit[0]["depth"] <= 3
    # and the bridged route exists in the graph itself
    assert (gw.id, child.id, "modbus_bridge") in model.edges


# ---- smart-building / IoT devices ------------------------------------------- #

def test_mdns_thermostat(model):
    m = by_ip(model)
    th = m["10.20.5.60"]
    assert "iot_device" in th.roles
    assert "ZerOT Thermostat" in th.hostnames
    assert any("_hap._tcp" in s for s in th.attrs.get("mdns_services", []))
    assert th.attrs.get("iot_platform") == "HomeKit"
    assert th.attrs.get("model") == "ZerOT"
    assert th.vendor == "Espressif Inc."
    assert th.zone(model.scope) == "L1"          # it's on the control subnet


def test_ssdp_thermostat(model):
    m = by_ip(model)
    th = m["10.20.5.61"]
    assert "iot_device" in th.roles
    assert th.vendor.startswith("Honeywell")
    assert th.attrs.get("upnp_server") == "Honeywell TH-IP UPnP/1.0"
    assert "uuid:zerot-Honeywell-TH-IP" in th.attrs.get("upnp_usn", "")


def test_mqtt_client_and_broker(model):
    m = by_ip(model)
    th = m["10.20.5.60"]
    assert "mqtt_client" in th.roles
    assert th.attrs.get("mqtt_client_id") == "home-svc/thermostat-lr"
    assert "home/livingroom/temp" in th.attrs.get("mqtt_topics", [])
    scada = m["10.20.7.20"]
    assert "mqtt_broker" in scada.roles
    ids = {ip: a.id for a in model.assets.values() for ip in a.ips}
    assert (ids["10.20.5.60"], ids["10.20.7.20"], "mqtt") in model.edges


def test_knx(model):
    m = by_ip(model)
    gw = m["10.20.5.63"]
    assert "knx_gateway" in gw.roles
    assert "knxgw" in gw.hostnames
    hub = m["10.20.5.62"]
    assert "knx_client" in hub.roles
    assert hub.vendor == "Google, Inc."


def test_iot_ot_findings(model):
    iot_findings = [f for f in model.findings if f["id"].startswith("iot-ot-")]
    assert len(iot_findings) >= 2               # esp thermostat + honeywell + knx devices
    sev = {f["severity"] for f in iot_findings}
    assert sev == {"medium"}
    # evidence carries the useful enrichment
    esp = [f for f in iot_findings if "10.20.5.60" in f["evidence"].get("ips", [])]
    assert esp and "Espressif Inc." == esp[0]["evidence"]["vendor"]


def test_mdns_querier_role(model):
    m = by_ip(model)
    assert "mdns_querier" in m["10.20.5.62"].roles


# ---- scope / active gating -------------------------------------------------- #

def test_scope_zone_resolution():
    s = Scope(SCOPE)
    assert s.zone_of("10.20.5.11") == "L1"
    assert s.zone_of("10.20.7.20") == "L2_L3"
    assert s.zone_of("10.20.9.30") == "Enterprise"
    assert s.zone_of("192.168.1.1") == "Unclassified"


def test_scope_purdue():
    s = Scope(SCOPE)
    assert s.purdue_of("L1") == "L0/L1"
    assert s.purdue_of("L2_L3") == "L2/L3"
    assert s.purdue_of("Enterprise") == "L4/L5"


def test_active_gating():
    s = Scope(SCOPE)
    assert s.active_decision("arp_ping") == "allow"
    assert s.active_decision("modbus_id") == "confirm"
    disabled = Scope({**SCOPE, "active": {"enabled": False, "techniques": {}}})
    assert disabled.active_decision("arp_ping") == "block"


def test_active_plan_only_known_techniques():
    s = Scope({**SCOPE, "active": {"enabled": True, "techniques": {"modbus_write": "allow"}}})
    tasks = ds.ActivePlanner(s).plan()
    assert all(t["technique"] in ds.ACTIVE_TECHNIQUES for t in tasks)


def test_run_active_dry_run_sends_nothing(model):
    plan = [{"technique": "tcp_probe", "ip": "10.20.5.12", "decision": "allow"}]
    res = ds.run_active(model, plan, execute=False, assume_yes=True)
    assert res["sent"] == 0
    assert res["skipped"] == 1


def test_run_active_blocks_unknown_technique(model):
    plan = [{"technique": "modbus_write", "ip": "10.20.5.12", "decision": "allow"}]
    res = ds.run_active(model, plan, execute=True, assume_yes=True)
    assert res["blocked"] == 1
    assert res["sent"] == 0


def test_run_active_confirm_requires_yes(model):
    plan = [{"technique": "tcp_probe", "ip": "127.0.0.1", "decision": "confirm"}]
    res = ds.run_active(model, plan, execute=True, assume_yes=False)
    assert res["sent"] == 0
    assert res["skipped"] == 1


# ---- exports ---------------------------------------------------------------- #

def test_dot_export(model):
    dot = model.to_dot()
    assert dot.startswith("digraph")
    assert "SCADA-SRV" in dot
    assert 'color="#e05252"' in dot           # write edges red
    assert "cluster_L1" in dot
    assert "cluster_Enterprise" in dot


def test_csv_and_md(model):
    csv_out = model.assets_csv()
    assert "SCADA-SRV" in csv_out
    assert "Apple" in csv_out
    md = model.report_md()
    assert "Unmanaged master device" in md
    assert "Enterprise-to-control path" in md


def test_save_load_roundtrip(tmp_path, model):
    p = tmp_path / "state.json"
    model.save(p)
    m2 = Model.load(p)
    assert len(m2.assets) == len(model.assets)
    assert len(m2.edges) == len(model.edges)
    assert {f["id"] for f in m2.findings} == {f["id"] for f in model.findings}


# ---- diff ------------------------------------------------------------------- #

def test_diff_detects_new_devices_and_edges(model, tmp_path):
    old = Model(Scope(SCOPE))
    old.ingest_pcap(FIXTURE)
    old_db = tmp_path / "old.json"
    old.save(old_db)

    # a second capture: same plant + a rogue contractor laptop polling the PLC
    import scapy.all as sa
    from scapy.utils import wrpcap
    pkts = list(sa.PcapReader(str(FIXTURE)))
    extra = []
    mac_r = "d4:8a:fc:aa:05:99"
    ip_r = "10.20.5.99"
    req = struct.pack(">HHHB", 500, 0, 6, 1) + bytes([3]) + struct.pack(">HH", 0, 4)
    resp = struct.pack(">HHHB", 500, 0, 9, 1) + bytes([3, 8]) + b"\x00" * 8
    extra.append(sa.Ether(src=mac_r, dst="00:80:f4:aa:05:12") / sa.IP(src=ip_r, dst="10.20.5.12") /
                 sa.TCP(sport=46000, dport=502, flags="PA", seq=1, ack=1) / sa.Raw(load=req))
    extra.append(sa.Ether(src="00:80:f4:aa:05:12", dst=mac_r) / sa.IP(src="10.20.5.12", dst=ip_r) /
                 sa.TCP(sport=502, dport=46000, flags="PA", seq=1, ack=1) / sa.Raw(load=resp))
    extra_pcap = tmp_path / "day2.pcap"
    wrpcap(str(extra_pcap), extra)

    new = Model(Scope(SCOPE))
    new.ingest_pcap(FIXTURE)
    new.ingest_pcap(extra_pcap)

    d = ds.diff_models(old, new)
    labels = [a["label"] for a in d["new_assets"]]
    assert "10.20.5.99" in labels
    rogue = [a for a in d["new_assets"] if a["label"] == "10.20.5.99"][0]
    assert "Espressif Inc." in rogue["vendor"]
    assert "master" in rogue["roles"]
    edge_strs = [f"{e['source_label']}->{e['target_label']}" for e in d["new_edges"]]
    assert any("10.20.5.12" in s for s in edge_strs)
    assert d["departed_assets"] == []


def test_diff_departed_and_no_change(model, tmp_path):
    old = Model(Scope(SCOPE))
    old.ingest_pcap(FIXTURE)
    # build a reduced model: only the BACnet packets
    import scapy.all as sa
    pkts = [p for p in sa.PcapReader(str(FIXTURE)) if p.haslayer(sa.UDP) and p[sa.UDP].dport == 47808]
    small = Model(Scope(SCOPE))
    small.ingest_packets(pkts)
    d = ds.diff_models(old, small)
    assert len(d["departed_assets"]) >= 10
    assert d["new_assets"] == []
    # identical models -> empty diff
    d2 = ds.diff_models(old, old)
    assert d2["new_assets"] == [] and d2["new_edges"] == []


# ---- live-mode pipeline parity ----------------------------------------------- #

def test_ingest_packets_recompute_equivalence(model):
    """ingest_packets (live path) must produce the same gateway children and
    findings as ingest_pcap (two-pass path) for identical packets."""
    import scapy.all as sa
    pkts = list(sa.PcapReader(str(FIXTURE)))
    live = Model(Scope(SCOPE))
    live.ingest_packets(pkts)
    pcap = Model(Scope(SCOPE))
    pcap.ingest_pcap(FIXTURE)
    assert {a.id for a in live.assets.values()} == {a.id for a in pcap.assets.values()}
    assert set(live.edges) == set(pcap.edges)
    kids = [a for a in live.assets.values() if "#" in a.id]
    assert len(kids) == 3       # u17, u18, d7 children present in live path too


# ---- active: modbus unit sweep against a fixture gateway ---------------------- #

def test_modbus_unit_sweep_against_fixture_gateway(model):
    """Fake Modbus/TCP gateway: unit 5 + 9 respond with device-id, unit 2
    answers illegal-function (exists), others -> gateway no-response 0x8B."""
    import threading

    def mbap_resp(txid, unit, payload):
        return struct.pack(">HHHB", txid, 0, 3 + len(payload), unit) + payload

    live_units = {5, 9}          # device-id responders
    exists_units = {2}           # illegal-function exception (device present)
    hit_log = []

    def serve():
        conn, _ = srv.accept()
        with conn:
            while True:
                try:
                    data = conn.recv(512)
                except OSError:
                    return
                if not data or len(data) < 8:
                    return
                unit = data[6]
                if unit in live_units:
                    # device-id basic: conformity 0x83 (individual), more-follows 0
                    body = bytes([0x2B, 0x0E, 0x01, 0x00, 0x83, 0x00, 5]) + b"PLCX" + b"\x00\x00"
                    conn.sendall(struct.pack(">HHHB", struct.unpack(">H", data[:2])[0], 0,
                                             3 + len(body), unit) + body)
                elif unit in exists_units:
                    conn.sendall(struct.pack(">HHHB", struct.unpack(">H", data[:2])[0], 0,
                                             4, unit) + bytes([0xAB, 0x01]))
                else:
                    conn.sendall(struct.pack(">HHHB", struct.unpack(">H", data[:2])[0], 0,
                                             4, unit) + bytes([0x8B, 0x01]))

    import socket as sk
    srv = sk.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    t = threading.Thread(target=serve, daemon=True)
    t.start()

    m2 = Model(Scope(SCOPE))
    res = ds._probe_modbus_unit_sweep("127.0.0.1", m2, port=port, units=range(1, 12), timeout=0.5)
    srv.close()
    assert res is not None
    assert set(res["units"]) == {2, 5, 9}
    # virtual children materialized from sweep results
    gw = m2.assets.get("ip:127.0.0.1")
    assert gw is not None and "modbus_gateway" in gw.roles
    kids = [a for a in m2.assets.values() if a.attrs.get("behind_gateway") == gw.id]
    assert {k.attrs.get("modbus_unit") for k in kids} == {2, 5, 9}




def test_cli_ingest_and_export(tmp_path):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(SCOPE))
    db = tmp_path / "state.json"
    r = subprocess.run([sys.executable, str(ROOT / "zerot.py"), "ingest", str(FIXTURE),
                        "--scope", str(scope_file), "--db", str(db)],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert "assets" in r.stdout
    r2 = subprocess.run([sys.executable, str(ROOT / "zerot.py"), "export", "--db", str(db),
                         "--format", "dot"], capture_output=True, text=True, timeout=60)
    assert r2.returncode == 0, r2.stderr
    assert "digraph" in r2.stdout


def test_cli_active_dryrun(tmp_path):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(SCOPE))
    r = subprocess.run([sys.executable, str(ROOT / "zerot.py"), "active", "--scope", str(scope_file)],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert "dry-run" in r.stdout


def test_bacnet_whois_probe_against_fixture_device():
    """Unicast who-is against a local fixture BACnet device: i-am reply must
    prove the device, capture its instance, and not leave a self-edge."""
    import socket as sk
    import threading
    srv = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3.0)
    port = srv.getsockname()[1]

    # i-am with device instance 1234, vendor 85 (Johnson Controls)
    objid = struct.pack(">I", (8 << 22) | 1234)
    apdu = bytes([0x10, 0x00, 0x0C]) + objid + bytes([0x19, 0x00, 0x29, 0x00]) \
        + bytes([0x3A]) + struct.pack(">H", 85)
    iam = bytes([0x81, 0x0B, 0x00, 0x16]) + bytes([0x01, 0x00]) + apdu

    def serve():
        try:
            data, addr = srv.recvfrom(2048)
            assert data[:4] == bytes([0x81, 0x0A, 0x00, 0x08]), "probe sent malformed who-is"
            srv.sendto(iam, addr)
        except sk.timeout:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    m = Model(Scope(SCOPE))
    res = ds._probe_bacnet_whois("127.0.0.1", m, port=port, timeout=1.5)
    t.join(timeout=2.0)
    assert res is not None, "probe returned None — no i-am parsed"
    assert res["devices"][0]["instance"] == 1234
    a = m.resolve(ip="127.0.0.1")
    assert a.attrs.get("bacnet_instance") == 1234
    assert a.roles and "bacnet_device" in a.roles
    assert (a.id, a.id, "bacnet") not in m.edges    # no self-edge artifact


def test_iec104_command_direction_counts_write():
    """A Type-45 (C_SC_NA_1 single-command) request must count as a write."""
    import scapy.all as sa
    m = Model(Scope(SCOPE))
    apci = struct.pack("<I", (0 << 16) | (0 << 1))          # I-format, seq 0/0
    asdu = struct.pack("<BBH", 45, 1, 1) + bytes([0x01]) + struct.pack("<H", 7)
    frame = bytes([0x68, 6 + len(asdu)]) + apci + asdu
    req = (sa.Ether(src="00:0c:29:aa:07:20", dst="74:f6:61:aa:05:33") /
           sa.IP(src="10.20.7.20", dst="10.20.5.33") /
           sa.TCP(sport=46001, dport=2404, flags="PA") / sa.Raw(load=frame))
    ack = (sa.Ether(src="74:f6:61:aa:05:33", dst="00:0c:29:aa:07:20") /
           sa.IP(src="10.20.5.33", dst="10.20.7.20", ttl=63) /
           sa.TCP(sport=2404, dport=46001, flags="PA") / sa.Raw(load=frame))
    m.ingest_packets([req, ack])
    e = m.edges[("00:0C:29:AA:07:20", "74:F6:61:AA:05:33", "iec104")]
    assert e.writes == 1


def test_s7_szl_probe_against_fixture_plc():
    """Mock S7 PLC speaking the s7-info handshake; probe must extract module,
    hardware, firmware, and identity strings from nmap-proven offsets."""
    import socket as sk
    import threading

    def s7_msg(payload):                       # TPKT(4) + payload
        return struct.pack(">BBH", 3, 0, 4 + len(payload)) + payload

    # --- build SZL responses; offsets are absolute over the FULL frame
    # (nmap parses TPKT-inclusive), so place bytes at abs-4 inside the body
    # that s7_msg() will append after the 4-byte TPKT header.
    def frame(n, proto=0x32):
        b = bytearray(n)
        b[7 - 4] = proto                        # nmap checks frame[7]
        return b

    r11 = frame(224)
    r11[31 - 4] = 0x11                          # szl id low byte
    r11[44 - 4:44 - 4 + 12] = b"CPU 315-2 PN/DP"        # module
    r11[72 - 4:72 - 4 + 18] = b"6ES7 315-2EH14-0AB0 "   # basic hardware
    r11[123 - 4], r11[124 - 4], r11[125 - 4] = 3, 2, 1  # firmware

    r1c = frame(240)
    r1c[31 - 4] = 0x1C
    r1c[40 - 4:40 - 4 + 16] = b"SIMATIC 300(1)\x00"     # system name
    r1c[74 - 4:74 - 4 + 16] = b"CPU 315-2 PN/DP\x00"    # module type
    r1c[108 - 4:108 - 4 + 12] = b"TankFarm A\x00"       # plant id
    r1c[142 - 4:142 - 4 + 11] = b"Siemens AG\x00"       # copyright
    r1c[176 - 4:176 - 4 + 17] = b"S C-B2A4 12345678\x00"  # serial

    srv = sk.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        with conn:
            def rd():
                h = conn.recv(4)
                if len(h) < 4:
                    return None
                want = struct.unpack(">H", h[2:4])[0] - 4
                b = b""
                while len(b) < want:
                    c = conn.recv(want - len(b))
                    if not c:
                        return None
                    b += c
                return h + b
            rd()                                # COTP CR -> CC
            conn.sendall(s7_msg(bytes([0x11, 0xe0, 0x00, 0x00, 0x00, 0x05, 0x00, 0xc0])))
            rd()                                # setup -> S7 ack-data (all-zero codes)
            conn.sendall(s7_msg(bytes([0x02, 0xf0, 0x80, 0x32, 0x03]) + b"\x00" * 11))
            rd()                                # SZL 11 req
            conn.sendall(s7_msg(bytes(r11)))
            rd()                                # SZL 1C req
            conn.sendall(s7_msg(bytes(r1c)))
        srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    m = Model(Scope(SCOPE))
    res = ds._probe_s7_szl("127.0.0.1", m, port=port, timeout=2.0)
    t.join(timeout=3.0)
    assert res is not None, "probe returned None — handshake or parse failed"
    assert res["module"] == "CPU 315-2 PN/DP"
    assert res["basic_hardware"] == "6ES7 315-2EH14-0AB0"
    assert res["firmware"] == "3.2.1"
    assert res["system_name"] == "SIMATIC 300(1)"
    assert res["plant_id"] == "TankFarm A"
    assert res["serial"] == "S C-B2A4 12345678"
    a = m.resolve(ip="127.0.0.1")
    assert a.attrs.get("s7_module") == "CPU 315-2 PN/DP"
    assert "s7_slave" in a.roles
    assert (a.id, a.id, "s7comm") not in m.edges    # no self-edge artifact


def test_evidence_provenance_on_assets_and_findings(model):
    """Every asset/edge/finding carries pcap file + frame number citations."""
    lap = model.assets.get("00:1E:C2:AA:05:88")
    assert lap is not None and lap.evidence, "no evidence recorded on contractor laptop"
    ev = lap.evidence[0]
    assert "ot_plant.pcap" in ev["source"] and isinstance(ev.get("frame"), int)
    # edge evidence: modbus master conversation laptop -> plc
    e = model.edges[("00:1E:C2:AA:05:88", "00:80:F4:AA:05:12", "modbus")]
    assert e.evidence and all("frame" in x for x in e.evidence)
    # findings cite provenance
    un = next(f0 for f0 in model.findings if f0["id"].startswith("unmanaged-"))
    assert un["evidence"]["provenance"]
    # save/load round-trips evidence
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        p = fh.name
    model.save(p)
    m2 = Model.load(p)
    os.unlink(p)
    lap2 = m2.assets.get("00:1E:C2:AA:05:88")
    assert lap2.evidence == lap.evidence
    e2 = m2.edges[("00:1E:C2:AA:05:88", "00:80:F4:AA:05:12", "modbus")]
    assert e2.evidence == e.evidence and e2.evidence_total >= e.evidence_total


def test_import_nmap_fuses_and_enriches(model):
    """nmap XML enriches passively-seen assets and adds unseen ones, with
    source-tagged evidence; down hosts skipped."""
    st = model.import_nmap("tests/fixtures/nmap_scan.xml")
    assert st["hosts"] == 2                       # 'down' host skipped
    scada = by_ip(model)["10.20.7.20"]
    # enriched: hostname, os guess, product version, open ports
    assert "scada-srv.packetlabs.local" in scada.hostnames
    assert scada.attrs["nmap_os"] == "Siemens SIMATIC S7-1500 PLC"
    assert scada.attrs["nmap_product"] == "1756-L83E ControlLogix"
    assert [102, 502, 44818] == [p[0] for p in scada.attrs["nmap_open_ports"]]   # sorted
    # evidence tags the nmap source
    nmap_ev = [e for e in scada.evidence if e["source"].startswith("nmap:")]
    assert nmap_ev and sorted(nmap_ev[0]["open_ports"]) == [102, 502, 44818]
    # unseen host added as nmap-only asset
    rogue = by_ip(model)["10.20.5.99"]
    assert "rogue-laptop" in rogue.hostnames
    assert any(e["source"].startswith("nmap:") for e in rogue.evidence)
    # passive evidence untouched: modbus edge still cites pcap frames
    e = model.edges[("00:1E:C2:AA:05:88", "00:80:F4:AA:05:12", "modbus")]
    assert any("ot_plant.pcap" in x["source"] for x in e.evidence)


def test_cve_enrichment_matches_identified_products(model):
    """Identified products get CVE findings citing the curated db; consumer
    gear gets none."""
    cve_findings = [x for x in model.findings if x["id"].startswith("cve-")]
    ab = next(a for a in model.assets.values() if a.attrs.get("enip_product"))
    hit = next(x for x in cve_findings if ab.id in x["assets"])
    assert hit["evidence"]["product"] == "Allen-Bradley ControlLogix 1756"
    assert hit["evidence"]["top_cves"], "no top CVEs surfaced"
    assert all(c["cvss"] >= 7.0 for c in hit["evidence"]["top_cves"])
    assert hit["severity"] in ("high", "medium")
    # consumer devices (laptop/thermostats) must NOT get CVE findings
    lap = model.assets.get("00:1E:C2:AA:05:88")
    assert not any(lap.id in x["assets"] for x in cve_findings)
    # provenance rides along
    assert hit["evidence"]["provenance"]
    # db generation date surfaced for report-time verification
    assert hit["evidence"]["db_generated"]


def test_cve_db_is_verified_source():
    """The shipped db must exist, be NVD-tagged, and have consistent shape."""
    db = ds.CVE_DB
    assert db.get("_meta", {}).get("source") == "NVD 2.0 API"
    n = 0
    for family, cves in db.get("products", {}).items():
        assert isinstance(cves, list) and cves, family
        for c in cves:
            assert c["id"].startswith("CVE-"), c
            assert c["url"].startswith("https://nvd.nist.gov/vuln/detail/"), c
            n += 1
    assert n >= 50, f"db too thin: {n}"
