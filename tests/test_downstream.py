"""Downstream tests: fixture-driven passive pipeline, roles, findings, zones, exports, gating."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import downstream as ds
from downstream import Model, Scope

FIXTURE = ROOT / "tests" / "fixtures" / "ot_plant.pcap"

SCOPE = {
    "name": "Downstream test plant",
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


# ---- CLI smoke --------------------------------------------------------------- #

def test_cli_ingest_and_export(tmp_path):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(SCOPE))
    db = tmp_path / "state.json"
    r = subprocess.run([sys.executable, str(ROOT / "downstream.py"), "ingest", str(FIXTURE),
                        "--scope", str(scope_file), "--db", str(db)],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert "assets" in r.stdout
    r2 = subprocess.run([sys.executable, str(ROOT / "downstream.py"), "export", "--db", str(db),
                         "--format", "dot"], capture_output=True, text=True, timeout=60)
    assert r2.returncode == 0, r2.stderr
    assert "digraph" in r2.stdout


def test_cli_active_dryrun(tmp_path):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(SCOPE))
    r = subprocess.run([sys.executable, str(ROOT / "downstream.py"), "active", "--scope", str(scope_file)],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert "dry-run" in r.stdout
