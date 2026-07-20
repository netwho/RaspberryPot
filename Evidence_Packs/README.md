# Evidence packs

Real attacks against a live honeypot sensor. Each pack is a self-contained ZIP —
the packets, the written analysis, machine-readable indicators, and a manifest
that lets you verify the file and reproduce the query.

> ⚠ **These captures contain live hostile traffic.** Open them in an isolated
> environment and do not casually fetch the URLs inside.

---

## Pick a pack

| # | Pack | Service | In one line | Size |
|---|---|---|---|---|
| **001** | [**IoT malware dropper**](001-telnet-iot-dropper/) | telnet | A Mirai-family bot logs in with a DVR default password and pulls its payload — the full loader script, start to finish, in 8 seconds. | 7.6 KB |
| **002** | [**`.env` secret harvester**](002-http-env-harvester/) | HTTP | 55 requests hunting for leaked `.env` and config files across every framework layout. No login, no shell — pure enumeration. | 88 KB |
| **003** | [**RDP research scanner**](003-rdp-research-scanner/) | RDP | An internet-wide scanner knocking on RDP. Included as the *baseline*: what a low-substance session looks like. | 2.6 KB |

Each pack directory has its own README with the analysis, the indicators, and
verification steps. Start with **001** if you only look at one — it is the
complete story from first packet to payload.

**New to this?** 001 and 003 are one TCP session each and small enough to read
packet by packet in Wireshark. 002 spans several days and is better approached
through `iocs.json` first.

---

## What is in every pack

| File | Purpose |
|---|---|
| `capture.pcap` | The packets. Wireshark, tshark, Zeek, Suricata — whatever you use. |
| `report.pdf` | The analysis written up: identity, activity, credentials, commands, files, and the exact query used to cut the capture. |
| `iocs.json` / `iocs.yaml` | Indicators, machine-readable. Same content, two formats. |
| `misp-event.json` / `.yaml` | MISP core format. **Event ▸ Import from ▸ MISP JSON**. |
| `SHA256SUMS` | `sha256sum -c SHA256SUMS` — verify nothing changed in transit. |
| `MANIFEST.txt` | Digests, the Arkime expression and window, handling notes. |

Format reference: [`docs/EVIDENCE-BUNDLE.md`](../docs/EVIDENCE-BUNDLE.md).

---

## Sanitisation

All published packs are **sanitised**. The sensor's own addresses are rewritten
to RFC 5737 / RFC 3849 documentation ranges (`192.0.2.x`, `2001:db8::x`) in both
the report and the PCAP; MAC addresses are replaced with locally-administered
values.

**The attacker's data is never altered** — addresses, ports, payloads and timings
are exactly as captured, because anything else would make the packs worthless for
correlation.

One limit worth knowing: packet *payloads* are not rewritten. Service banners,
host keys and certificates inside the traffic are untouched. Sanitisation removes
the obvious identifiers; it is not anonymisation.

---

## Verify any pack

```sh
unzip rpot-<ip>-<utc>-sanitised.zip -d pack && cd pack
sha256sum -c SHA256SUMS
```

`MANIFEST.txt` carries the Arkime expression and UTC window used to cut the
capture, so the result is reproducible against any capture covering that window —
not only mine.

---

The full analysis walkthrough that produced these is in
**[fantasticfour.md](../fantasticfour.md)**.

<!-- ────────────────────────────────────────────────────────────────────────
     ADDING THE NEXT PACK

     1. Create NNN-short-slug/ with the ZIP and a README.md.
     2. Add one row to "Pick a pack" — ONE line of description, no more. This
        page is a menu; the detail belongs in the pack's own README.
     3. Keep the numbering. Bundle filenames carry timestamps, which are precise
        and useless for referring to a pack in conversation.
     4. Defang URLs (hxxp://) in every human-facing page. The bundle keeps them
        live because tooling needs them parseable.
     5. Variety over volume: a second telnet loader teaches little, an SMB or
        MySQL case teaches a lot.
     ──────────────────────────────────────────────────────────────────────── -->
