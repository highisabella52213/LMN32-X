# Lumen v32 verification

Verified in a clean local runtime:

- Python syntax compilation: pass
- Node edge syntax: pass
- Deterministic project suite: **31/31 pass**
- Fresh boot from empty state: pass
- Admin login and capability registry: pass
- Managed Xray lifecycle with generated config: pass
- Raw public edge to loopback Xray WebSocket upgrade: pass
- Raw public edge to loopback Xray HTTPUpgrade: pass
- XHTTP session-path rewrite and proxying: pass
- Native legacy VLESS relay and exact outbound fail-closed test: pass
- Railway installer contract: pass

## End-to-end Xray matrix

Each case used a real local Xray client, crossed the Lumen edge, authenticated
against the generated server inbound and fetched `http://example.com` through
the server outbound:

| Protocol | WebSocket | HTTPUpgrade | XHTTP |
| --- | --- | --- | --- |
| VLESS | PASS | PASS | PASS |
| VMess | PASS | PASS | PASS |
| Trojan | PASS | PASS | PASS |

Result: **9/9 PASS**.

The long-running WebSocket endurance program is in `benchmarks/` and is kept
separate from the deterministic contract suite.