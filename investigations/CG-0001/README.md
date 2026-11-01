# CG-0001: UK SMS-phishing redirect chain on generated domains

| | |
|---|---|
| **Cluster** | CG-0001 in campaign-graph (36 hosts, density 0.959) |
| **Status** | Unattributed. Active 21 Sep – 29 Oct 2026; landing pages suspended by 1 Nov 2026 |
| **Assessed activity** | SMS phishing (smishing) aimed at UK mobile users, through an affiliate-style click tracker |
| **Collection** | Passive only: ThreatFox, RDAP registration records, certificate transparency, public reporting. No domain was resolved, visited or scanned |
| **Analyst** | Barnabas · 1 November 2026 |

Rendered page: [CG-0001 Investigation](https://campaign-graph.onrender.com/reports/cg0001.html)

## Key findings

1. **The cluster is a smishing redirect chain, not malware.** ThreatFox labels all 46
   records "Unknown malware / payload_delivery". The URLs show something else: a short
   generated domain, then a click tracker carrying an SMS cost macro (`%sms_cost%`) and a
   UK mobile number, then a landing page under `/pa/UK/`. *High confidence.*
2. **One operator built it in three registration waves** (21–28 Sep, 13–18 Oct, 21–24
   Oct), switching registrar and DNS setup each time. What links the waves is the naming:
   all 38 generated domains are 7–8 letters, alternating vowel and consonant (`ihelaha`,
   `egulene`, `oramosi`). The URL conventions and reporting times are shared too.
   *Moderate confidence.*
3. **The operator already held the victims' personal data before sending.** One tracker
   URL carries a UK resident's first name, surname, home address, email and mobile number
   as pre-filled parameters. That points to a bought or breached lead list, not data
   typed into a phishing form. *Moderate confidence*, based on one complete example.
4. **Domains were aged before use.** The median gap from registration to first report
   is 10 days (range 3–37). The oldest wave served only `/opt/out` pages. *High
   confidence for the timing; low confidence for why.*
5. **Partly disrupted already.** Both `.top` landing domains are on registry
   `serverHold`. The 36 short domains and the tracker were still registered and
   unsuspended on 1 Nov 2026.

## How campaign-graph found it

CG-0001 was the largest cluster with no family label. The graph joined its hosts on
shared custom URI paths, `/L12qt0W` (35 hosts) and `/opt/out` (10 hosts), which count as
strong pivots. No family label came from the feeds, so it surfaced in the explorer's
**Leads** view.

[Open CG-0001 in the explorer](https://campaign-graph.onrender.com/#CG-0001).

It is a fair test of the tool. Without labels, the cluster still matched a real
operation, and the investigation below confirmed the grouping with evidence the graph
never saw: registration records and naming.

## The chain

```
SMS to a UK mobile
  └─ https://<generated>.com/L12qt0W           short link; the path is the click_id
       └─ https://now.trckthepage[.]com/<uuid>?click_id=L12qt0W&var2=…&var9=44…&cost=%sms_cost%
            └─ https://<generated>.top/pa/UK/<n>/?srv=eu&domain=now.trckthepage[.]com&cep=…&lptoken=…
                                               landing page (not visited)
```

- **The short-link path is the tracker's `click_id`.** `L12qt0W` appears on 35 domains,
  so it is a batch or campaign token, not a per-recipient one. A second token,
  `Fnc12IU`, appears once.
- **The tracker's parameters** are the generic slots ad trackers use (`var2`…`var11`,
  `lptoken`, `cep`). In the observed URLs, those slots carry the recipient's mobile
  number (`var9`, UK `44 7…` format) and, in one case, name, address and email.
- **`%sms_cost%`** is an unfilled cost macro, left in the URL by whatever system sent
  the SMS. It shows the traffic was bought or sent as SMS and tracked like paid ads.
- **`/opt/out`** appears only on wave A domains. Fake opt-out links are common in
  smishing; one plausible use is confirming that a number is live when someone replies
  or clicks. This is unconfirmed, as no page content was collected.

Public reporting on UK smishing ([Hunt.io: DPD-themed operation][hunt];
[Resecurity][reso] and [Infosecurity Magazine][infosec] on Smishing Triad) does not
mention this tracker domain or these URL parameters. The tracker-macro design and the
pre-filled victim data differ from the per-brand phishing kits in that reporting. No
attribution is made.

## Timeline (UTC)

| Date | Event |
|---|---|
| 27 Jul 2026 | `iconado[.]com` has a GoDaddy certificate: an earlier registration, so likely a dropped domain re-registered |
| 21–28 Sep | **Wave A**: 10 domains, NameSilo, Cloudflare DNS. Let's Encrypt wildcard certificates issued within the hour of each registration |
| 13 Oct | `oramosi[.]top` (landing) registered, Openprovider |
| 18 Oct | **Wave B**: 9 `.com` + `pibifaka[.]top` (landing), Registrar.eu / Openprovider, registrar default DNS |
| 21–24 Oct | **Wave C**: 17 domains, Key-Systems, Cloudflare DNS |
| 24 Oct 06:12 | Tracker `trckthepage[.]com` registered, Key-Systems |
| 28 Oct 09:00–10:00 | 32 records reported to ThreatFox by one reporter (`/L12qt0W`, tracker and landing URLs) |
| 29 Oct 06:00–07:00 | 19 more records, including all 10 `/opt/out` URLs (wave A) |
| by 1 Nov | Both `.top` landing domains on `serverHold` |

## Infrastructure

| Wave | Registered | Registrar | DNS | Domains | Seen paths |
|---|---|---|---|---|---|
| A | 21–28 Sep | NameSilo | Cloudflare | 10 | `/L12qt0W`, `/opt/out` |
| B | 13–18 Oct | Registrar.eu / Openprovider | registrar default | 9 + 2 `.top` landers | `/L12qt0W`, `/pa/UK/` |
| C | 21–24 Oct | Key-Systems | Cloudflare | 17 + tracker | `/L12qt0W`, `/Fnc12IU` |

**Name generator.** All 38 generated domains (tracker excluded) alternate vowel and
consonant, are 7 or 8 letters long, and 37 of them start with a vowel. A pattern this
narrow surviving three registrar changes is the strongest link between the waves.

**Certificates.** Wave A shows automated provisioning: 9 of its 10 domains got a
Let's Encrypt wildcard certificate (`*.domain`) within an hour of registration. Wave B
has 3 such certificates; 7 domains returned none and 1 lookup failed. In wave C, crt.sh
returned no certificate for 14 domains and failed for 3; the one hit is `iconado[.]com`'s
older GoDaddy certificate. Missing certificates are a collection gap, not evidence of
plain HTTP: the reported URLs use HTTPS.

## Hypotheses and confidence

| # | Hypothesis | Confidence | For | Against / gaps |
|---|---|---|---|---|
| H1 | Delivered by SMS to UK mobiles | **High** | `%sms_cost%` macro; UK mobile numbers in `var9`; `/pa/UK/` landing path | Lure text not collected |
| H2 | One operator across waves A–C | **Moderate** | Same name generator, `click_id` convention and tracker; reported together | Three registrars; all records from one reporter (see caveats) |
| H3 | Operator held victim data before sending | **Moderate** | Name, address, email and phone pre-filled in a tracker URL | One complete example |
| H4 | Wave A `/opt/out` pages validate live numbers | **Low** | Fits wave A's role and common smishing practice | No page content |
| H5 | Linked to Smishing Triad or another named group | **Not assessed** | — | No overlap found in public reporting |

## Caveats

- **Single reporter.** All 51 ThreatFox records (46 on cluster domains, 5 tracker and
  landing URLs) come from one reporter in two batches,
  so part of the cluster's coherence may reflect how one person submitted them.
  Registration and naming evidence was checked independently to counter this, and it
  holds.
- **Feed label is wrong.** "Unknown malware / payload_delivery" describes no malware.
  This is phishing. A pipeline trusting the label would misfile it.
- **Nothing was visited.** Lure text, landing-page brand and payment flow are unknown.
  Collecting them safely would mean a sandboxed browser from a UK mobile IP.
- **Victim data.** One record holds a UK resident's personal data. It is redacted
  everywhere in this repository and in the published explorer. The original record
  stays visible on ThreatFox.

## What would change this assessment

- The lure text or landing brand (for example a parcel, toll or tax refund theme) would
  allow comparison with known kits and could support attribution.
- Domains with the same name pattern registered at other registrars, or with other
  `click_id` values, would test H2 and size the operation.
- Wave C certificates appearing in CT with the same issuer pattern as wave A would
  strengthen the single-operator link.

## Indicators

Defanged. Victim data removed.

**Tracker:** `trckthepage[.]com` (`now.` subdomain)
**Landing:** `oramosi[.]top`, `pibifaka[.]top`

**Short-link domains (wave A):** icubome, ihelaha, ikoduga, isanado, isanobe, itibile,
ivogamo, owafozo, ozivoto, ufuyaje — all `[.]com`
**Wave B:** eguyuwe, idiyoso, ijamecu, ojaleje, ojumapu, ufuhefu, ujexixa, utolapu,
uvupofi — all `[.]com`
**Wave C:** egulene, ekiceda, esirola, esuxofe, ewoyovo, ewufape, eyivowa, iconado,
ihufito, ofovema, ogijoho, orulere, osekawe, ubuwibu, uvozami, uxodivi, uyonapa — all
`[.]com`

**URL patterns**

- `^https://[a-z]{7,8}\.(com|top)/(L12qt0W|Fnc12IU|opt/out)$`
- tracker query containing `click_id=` and `cost=%sms_cost%`
- landing path `/pa/UK/<digits>/?srv=eu&domain=`

## Detection ideas

- **Mail and SMS gateways:** flag newly registered 7–8 letter domains that alternate
  vowel and consonant, in messages to UK numbers. Expect false positives on real words;
  combine with domain age under 45 days.
- **Proxy and DNS logs:** block or alert on the tracker domain, and on any URL holding
  an unfilled `%…_cost%` macro.
- **Brand protection:** the `/pa/<country>/` landing convention with `srv=` and
  `lptoken=` may recur for other countries; watch for `/pa/IE/`, `/pa/US/`.

## Lessons fed back into campaign-graph

- Feed URLs can hold victim personal data in query strings. The explorer now shows
  indicator URLs without query strings, and raw investigation data stays out of git.
- Domain-name shape (this vowel–consonant generator) linked infrastructure the URL
  pivots alone did not. A `nameshape:` weak pivot is on the roadmap.

## Sources

ThreatFox API (`search_ioc`); RDAP via rdap.org; crt.sh and SSLMate Cert Spotter
certificate transparency; public reporting:
[Hunt.io][hunt], [Resecurity][reso], [Infosecurity Magazine][infosec].

[hunt]: https://hunt.io/blog/massive-smishing-campaign-governments-postal-telecoms
[reso]: https://www.resecurity.com/blog/article/smishing-triad-is-now-targeting-toll-payment-services-in-a-massive-fraud-campaign-expansion
[infosec]: https://www.infosecurity-magazine.com/news/smishing-triad-toll-payment-scams/
