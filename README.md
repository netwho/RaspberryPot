<p align="center">
  <img src="docs/img/banner.png" alt="RaspberryPot — real attacks, real packets, shareable evidence" width="100%">
</p>

# RaspberryPot

**A multi-service honeypot on a Raspberry Pi, built to collect real-world PCAPs of real attacks.**

SSH, Telnet, HTTP, SMB, RDP, FTP and MySQL, deliberately exposed on isolated
hardware behind a firewall, with continuous full-packet capture behind it.
Everything an attacker does is recorded twice: once as structured events — what
they typed, what they fetched, whether the login was accepted — and once as raw
packets.

![Console dashboard](docs/img/console-dashboard.png)
<!-- SCREENSHOT: the dashboard on a busy day. Event counter, service breakdown,
     top attackers. This is the "why bother" picture — lead with volume. -->

---

## Why this exists

I wanted a library of packet captures of **actual attacks**. Not lab traffic,
not a replayed sample set, not a vendor's curated PCAP of the week — hostile
traffic arriving unprompted, in order, exactly as it hit the wire.

You cannot download that. Public capture repositories are mostly synthetic,
years old, or stripped to the point of uselessness. The only reliable way to get
current hostile traffic is to stand something in its path and let it be attacked.

So that is what this is: a lure interesting enough to be attacked properly,
instrumented well enough that the resulting traffic is worth keeping.

The unexpected part was what happened next. In under four weeks the sensor
logged more than **four million events**. Collection stopped being the problem
almost immediately, and *selection* became it — finding the twelve packets that
matter inside a two-terabyte lake. Most of the engineering in this project is
about that second problem, not the first.

The full write-up of how that gets solved — honeypot, Arkime, Wireshark and
MISP working together — is in **[fantasticfour.md](fantasticfour.md)**.

---

## Architecture

![Architecture](docs/img/architecture.png)

Two Raspberry Pis and a capture appliance, split by trust:

| Zone | Host | Runs |
|---|---|---|
| **DMZ** | Raspberry Pi 4 | The honeypot services + a management API. Nothing else. Reachable from the internet; reaches nothing inbound. |
| **Perimeter** | Protectli appliance | All perimeter traffic off a SPAN port to a 1 TB SSD, feeding **Arkime** + OpenSearch (Malcolm). Captures continuously — no trigger, no decision at capture time. |
| **Trusted** | Raspberry Pi 5 | The analysis console: a local mirror of the sensor's events, the Arkime integration, evidence-bundle export. Never exposed. |
| **Trusted** | — | **MISP**, for publishing what comes out. |

The two Pis share nothing but a one-way sync: the console pulls events from the
worker over an authenticated API. The worker holds no analysis state, has no
route into the trusted network, and can be rebuilt from scratch in minutes —
which is the point of putting it in the DMZ in the first place.

Service ports are NATed and firewalled to the honeypot individually, so exposure
is explicit rather than accidental.

### The services

Cowrie fronts SSH and Telnet; the rest are purpose-built emulations sharing a
common event contract. Each is a decoy, not a real service — an attacker gets a
convincing enough surface to reveal intent, and nothing that could be used to
pivot.

| Service | What it presents | What it captures |
|---|---|---|
| SSH / Telnet | Cowrie shell on an embedded-Linux persona | Credentials, full command lines, download attempts + payload hashes |
| HTTP | A generic web server with common CMS paths | Requests, probed paths, injected payloads |
| SMB | File shares with decoy documents | Share enumeration, file access, client hostnames |
| RDP | A Windows desktop image | Connection cookies (`mstshash`), credentials, client fingerprints |
| FTP | Anonymous + authenticated FTP | Credentials, commands, uploads |
| MySQL | A MySQL server banner | Credentials, queries, database enumeration |

---

## Finding the interesting session

Four million events is not a dataset, it is a haystack. The console exists to
make one session findable, and it offers several routes to the same place —
because "interesting" means something different depending on what you are doing.

![Attacker list](docs/img/console-attackers.png)
<!-- SCREENSHOT: the attacker list, sorted, with filters visible. -->

- **Live log** — everything as it lands, filterable by service and event type. Good for watching a campaign start.
- **Event list** — the full history, filterable and drillable. Good when you know what you are looking for.
- **Attacker list** — one row per source, with lifetime counters, geolocation, ASN and reputation. Good for "who is loudest".
- **Map view** — attacks plotted by origin, sized by volume. Good for triage by instinct: the biggest circle attached to the noisiest service is usually worth a look.
- **Session list** — every TCP session, classified by *what it actually contained*: did commands run, was a payload fetched, or was it just a probe?

![Session activity tiers](docs/img/console-sessions.png)
<!-- SCREENSHOT: the session list with the activity column visible — the
     content / payload / auth / probe badges. Best single picture of the
     triage problem: mostly hollow circles, a few filled. -->

That last one turned out to matter most. A telnet scanner opens thousands of
sessions and only a fraction get past the login prompt. Sorting by *substance*
rather than by volume takes triage from "read 2,500 sessions" to "read the
eleven that did something".

Open one and the detail panel shows what that attacker did — credentials,
commands, files, HTTP paths, SQL, RDP and SMB activity — with the packet-capture
integration in the same view.

![Attacker detail](docs/img/console-attacker-detail.png)
<!-- SCREENSHOT: attacker detail with the Arkime bar and the activity panels.
     Pick an attacker with commands so the panels are populated. -->

Select a single session there and everything below follows it: the panels, the
event list, the Arkime query, and the exported report all narrow to that one TCP
connection.

---

## The evidence bundle

The output of all of this is a single ZIP, scoped to whatever is selected — a
whole attacker, one protocol, or one session:

```
rpot-<ip>-<utc>[-sanitised].zip
│
├── capture.pcap        Raw packets from Arkime, filtered to scope
├── report.pdf          Human-readable analysis (WeasyPrint, A4)
├── iocs.json           Machine-readable indicators
├── iocs.yaml           …the same, in YAML
├── misp-event.json     MISP core-format Event, importable as-is
├── misp-event.yaml     …the same, in YAML
├── SHA256SUMS          coreutils format — `sha256sum -c SHA256SUMS`
└── MANIFEST.txt        Digests, the query used to cut the capture, handling notes
```

![Evidence report](docs/img/report-3pages.png)

Format reference: **[docs/EVIDENCE-BUNDLE.md](docs/EVIDENCE-BUNDLE.md)**.

Two properties worth calling out:

**Reproducible.** The manifest carries the exact Arkime expression, tag and UTC
window used to cut the capture, plus the PCAP's own SHA256. A recipient with
their own Arkime can re-run the query and verify they received what I produced.

**Sanitised by default.** My sensor's own addresses are rewritten to RFC 5737 /
RFC 3849 documentation ranges in both the report *and* the PCAP. The attacker's
addresses, ports, payloads and timings are never touched — altering those would
make the bundle worthless for correlation. Note the limit: packet *payloads* are
not rewritten, so banners, host keys and certificates inside the traffic can
still identify a sensor. Sanitisation removes the obvious identifiers; it is not
anonymisation.

---

## Sample evidence packs

Three packs are published in **[`/reports`](reports/)** for anyone who wants to
work with real hostile traffic — open them in Wireshark, or point whatever reads
JSON or YAML at the indicator files.

| Pack | Service | What it shows |
|---|---|---|
| `rpot-42_232_28_201-…` | Telnet | IoT malware dropper — default credentials, shell probing, staged payload fetch |
| `rpot-80_94_95_211-…` | HTTP | `.env` secret harvester — 55 config-file paths, no login, pure enumeration |
| `rpot-66_228_35_180-…` | RDP | Research scanner probing RDP — short, quiet, useful as a baseline |

See the [reports index](reports/README.md) for details on each.

---

## Status of the code

**Published today:** evidence bundles and reports.
**Not published yet:** the honeypot source and Docker configuration.

This is not coyness about a work in progress — the code runs a live sensor and
has for months. It is that publishing *this particular* code has consequences
that publishing a web app does not, and I would rather work through them than
discover them afterwards.

### What has to be settled first

**Fingerprinting.** A honeypot's value depends on not being recognised as one.
Publishing the source hands anyone the exact banners, timing behaviour, decoy
filesystem and shell responses my sensor presents — and, by extension, everyone
else's who runs it unmodified. Cowrie already has this problem and handles it by
making the persona configurable. Mine needs the same treatment before release:
every identifying string in a config file, none in the source.

**Secrets and deployment.** API keys, password hashes and host addresses need to
be provably out of the tree, with a setup path that generates them rather than
shipping defaults. A honeypot with a default credential is not funny.

**Safe defaults.** The current build assumes my network layout — an isolated
DMZ, firewalled per-port NAT, no route inbound. Someone standing this up on a
flat home network with UPnP enabled would be exposing a real machine to the
internet while believing they were safe. That has to be hard to get wrong before
it is easy to install.

**Legal and ethical footing.** Running a honeypot means deliberately receiving
attack traffic and storing what may include third-party data. That is
jurisdiction-dependent, and I would rather ship documentation about it than let
people find out on their own.

### Roadmap

1. Persona and configuration split — every fingerprintable string externalised
2. Clean deployment: generated secrets, network preflight checks, documented topology requirements
3. Source release (Apache-2.0 intended)
4. Docker Compose configurations for both roles
5. Guidance on running one responsibly

If you want to influence the order, open an issue — it is genuinely the most
useful input I get.

---

## Read more

- **[fantasticfour.md](fantasticfour.md)** — the full analysis walkthrough: one real attack from noise to shareable indicators, using the honeypot, Arkime, Wireshark and MISP together
- **[docs/EVIDENCE-BUNDLE.md](docs/EVIDENCE-BUNDLE.md)** — bundle format reference
- **[reports/](reports/)** — published evidence packs

---

## Licence

<!-- DECIDE BEFORE PUBLISHING — add the matching LICENSE files. A README claim
     is not a licence. CC BY 4.0 for data / Apache-2.0 for code are sensible
     defaults; GPL-3.0 if you would rather the code stay copyleft. -->

- **Reports and data:** Creative Commons Attribution 4.0 (CC BY 4.0)
- **Code, once released:** Apache License 2.0

## Contact

Issues and discussions are open. If you use a capture for teaching or research I
would like to hear about it — not as a condition, just because it is the most
useful feedback I get.

<!-- ────────────────────────────────────────────────────────────────────────
     SCREENSHOTS TO TAKE  (docs/img/)

     console-dashboard.png       Dashboard on a busy day — volume up front
     console-attackers.png       Attacker list, sorted, filters visible
     console-sessions.png        Session list with the activity tier column
     console-attacker-detail.png Detail panel: activity panels + Arkime bar
     console-map.png             Map view — optional, referenced in prose only
     console-live-log.png        Live log — optional, referenced in prose only

     Already in place: architecture.png, report-3pages.png

     BEFORE PUBLISHING ANY SCREENSHOT: check for the sensor's own IP/hostname,
     the Arkime host, and any worker ID. The bundle sanitiser does not cover
     screenshots.
     ──────────────────────────────────────────────────────────────────────── -->
