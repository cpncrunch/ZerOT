# Downstream

Passive-first OT/ICS asset discovery with BloodHound-style graphing. Maps
control networks layer by layer — including PLCs hidden behind Modbus/TCP
gateways, DNP3 data concentrators, and routed subnets — from packet captures or
live sniffing, with a strictly gated, read-only active layer.

Single-file Python backend + single-file d3 UI. No build step. Fully
air-gap capable (d3 vendored, OUI database bundled, zero external calls).

## What it detects

| Layer | Source | Output |
|---|---|---|
| Devices | Ethernet/ARP/DHCP/LLDP/NBNS/PN-DCP | assets with MAC↔IP, vendor (IEEE OUI), hostnames |
| Conversations | Modbus, S7comm, EtherNet/IP, DNP3, OPC UA, BACnet, PROFINET RT | directed master→slave edges, write counts, exception counts |
| Products | CIP Identity (listIdentity), PN-DCP, DHCP | product names ("1756-L83E"), station names |
| **Hidden layers** | Modbus unit IDs (>1 unit = gateway; each unit = child PLC) | virtual child assets + bridge edges |
| **Hidden layers** | DNP3 link addresses (>1 dst = data concentrator; each link = child RTU) | virtual child assets + bridge edges |
| **Hidden layers** | IP TTL (initial-guess 64/128/255) | `inferred_hops`, `last_hop_router` on routed assets |
| Purdue zones | scope file CIDRs | zone + Purdue level per asset |
| Risk | consumer-vendor device in OT zone, rogue OT master, enterprise→control session, write activity | findings (high/medium/info) |
| Attack paths | BFS from enterprise masters to PLC/RTUs across all edges incl. bridges | multi-hop enterprise→PLC paths |

## Install

```
uv venv && source .venv/bin/activate   # or any Python 3.11+
pip install scapy flask
sudo apt install graphviz              # optional, for svg/png export
```

## Quick start (synthetic demo plant)

```
# regenerate the 54-packet known-answer fixture
python3 scripts/gen_ot_pcap.py

# passive ingest with Purdue zoning
python3 downstream.py ingest tests/fixtures/ot_plant.pcap --scope data/scope.example.json

# explore
python3 downstream.py serve --scope data/scope.example.json
# -> http://127.0.0.1:8756  (graph, filters, findings, Attack paths button)

# exports for the report
python3 downstream.py export --format md    # findings + assets + paths
python3 downstream.py export --format svg -o plant.svg
python3 downstream.py export --format csv -o assets.csv
```

## Live capture

```
sudo python3 downstream.py live --iface eth1 --scope scope.json
```

## Layer crawling

```
python3 downstream.py crawl --scope scope.json            # dry-run: shows next targets
sudo python3 downstream.py crawl --scope scope.json --execute --yes
```

Crawl analysis is driven by what the graph already knows:
1. routed subnets (TTL-observed `last_hop_router`) → probe the unseen /24,
2. gateway/concentrator assets → enumerate unit IDs / link addresses,
3. out-of-scope IPs seen in conversations → surface for ROE review before probing.

Each round only uses the gated read-only techniques (`arp_ping`, `tcp_probe`,
`modbus_id`, `enip_list`); the next round's targets are recomputed from what
the previous round learned. It stops when no new targets appear.

## Scope file (ROE boundary)

```json
{
  "name": "Plant A",
  "zones": {"L1": ["10.20.5.0/24"], "L2_L3": ["10.20.7.0/24"], "Enterprise": ["10.20.9.0/24"]},
  "excluded": ["10.99.0.0/16"],
  "active": {
    "enabled": true,
    "techniques": {"arp_ping": "allow", "tcp_probe": "confirm",
                    "modbus_id": "confirm", "enip_list": "allow"}
  }
}
```

- `allow`   — in-scope, low-risk; runs with `--execute`
- `confirm` — needs `--yes` as explicit acknowledgement
- `block`   — never runs (also: active disabled ⇒ everything blocked)

**Write-class probes do not exist in this tool.** The technique registry is a
closed set of read-only discovery methods; unknown technique names are hard
blocked at execution time.

## API (serve mode)

| Method | Path | Purpose |
|---|---|---|
| GET | /api/graph | nodes/links/findings |
| GET | /api/paths | enterprise→PLC multi-hop paths |
| GET | /api/events | ingest/active event log |
| POST | /api/pcap | `{"paths": [...]}` server-side pcap ingest |
| POST | /api/active/plan | plan with allow/confirm/block counts |
| POST | /api/active/run | `{"execute": bool, "yes": bool}` |
| GET | /api/export/{dot,svg,png,csv,edges.csv,md,json} | exports |

## Testing

```
python3 -m pytest tests/ -q
```

31 tests over the synthetic known-answer fixture: vendors, roles, edges,
gateway/concentrator virtual children, router-guard, TTL hop inference, attack
paths, active gating (dry-run, unknown-technique block, confirm-requires-yes),
exports, save/load roundtrip, CLI smoke.

## Safety posture

- Passive ingest is read-only by construction.
- Active layer is dry-run by default; gated per technique; capped (`max_tasks`,
  inter-probe interval); read-only techniques only.
- Routed-traffic identity: a MAC claiming IPs across /24s is treated as a
  last-hop router, never merged into the remote host's identity (and
  LLDP-learned routers are never overwritten).
- All findings are labeled as observed-conversation inferences; the report
  carries an explicit non-claims section.

## Limitations

- CIP identity parsing covers listIdentity responses (fixed layout).
- S7 write detection covers Job requests with function group 0x12/0x01 (write
  var); not all S7 write encodings.
- TTL hop inference assumes initial TTL of 64/128/255.
- Virtual children represent protocol-level identities; they are not separate
  IP assets and cannot be probed directly — probe the gateway instead.
