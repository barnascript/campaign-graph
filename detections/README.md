# Detections

Google SecOps (Chronicle) YARA-L 2.0 rules built from the investigations, so a
finding ends as something a defender can run.

| Rule | Severity | Fires on | Source |
|---|---|---|---|
| [`cg0001_uk_smishing_chain`](yaral/cg0001_smishing_chain.yaral) | Medium | HTTP or DNS to a CG-0001 domain, a URL carrying the tracker's `cost=%sms_cost%` macro, or the `/pa/<CC>/<n>/?srv=…&domain=` landing convention | [CG-0001](../investigations/CG-0001/README.md) |
| [`cg0001_namegen_short_link_hunt`](yaral/cg0001_namegen_hunt.yaral) | Low (hunting) | DNS for a `.com`/`.top` name shaped like the operator's generator (minus a 2,501-name allowlist), then, within 15 minutes, HTTP from the same device to that name with a single 7-character token path | CG-0001 name-generator finding |

## Install

1. **Reference lists.** In Google SecOps, create two string lists:
   `cg0001_domains` from [`reference_lists/cg0001_domains.txt`](reference_lists/cg0001_domains.txt)
   (40 entries) and `cg0001_namegen_allowlist` from
   [`reference_lists/cg0001_namegen_allowlist.txt`](reference_lists/cg0001_namegen_allowlist.txt)
   (2,501 entries). `//` lines are comments.
2. **Rules.** Paste each `.yaral` file into the Rules Editor, save, and run it
   as a retrohunt over the last 30 days before enabling it live.

The rules use standard UDM fields (`target.hostname`, `target.url`,
`network.dns.questions.name`, `principal.hostname`) that web-proxy and DNS
parsers populate.

## How they were tested

No Google SecOps instance was available, so the rules were **not** run in
SecOps. What was tested:

- **Regexes.** `tests/test_vt_and_rules.py` reads each regex out of the `.yaral`
  file itself and checks it against positives from the investigation and
  near-miss negatives. The test fails if a rule edit breaks a pattern. All the
  patterns use only RE2 features, the regex engine YARA-L runs.
- **False positives of the hunting pattern** against the Tranco top-1M
  legitimate domains: see below.
- **Reference list** matches the investigation's 39 domains plus the tracker
  host.

Syntax follows the YARA-L 2.0 documentation. Expect to adjust field names to
your parsers before enabling.

## False-positive check: the name-generator pattern

The generator pattern (7–8 letters, strictly alternating vowel and consonant,
`.com` or `.top`) was run against the [Tranco](https://tranco-list.eu) list of
the top 1 million legitimate domains:

| Slice | Names matching | Rate |
|---|---|---|
| Top 10,000 | 35 | 0.35% |
| Top 100,000 | 318 | 0.32% |
| Top 1,000,000 | 2,501 | 0.25% |
| CG-0001 generated domains | 38 of 38 | 100% |

The shape alone is **not** enough: it matches `alibaba.com`, `bilibili.com`,
`politico.com` and other real sites. So the hunting rule does three things:

1. skips the 2,501 matching Tranco names (`cg0001_namegen_allowlist`);
2. requires an HTTP request to the same name with a single 7-character token
   path within 15 minutes (the `click_id` shape: `/L12qt0W`);
3. runs at low severity, as a hunting lead rather than an alert.

None of the 38 CG-0001 domains is in the Tranco list, so the allowlist does not
reduce recall on known infrastructure. Rebuild the allowlist with
`python3 detections/build_allowlist.py`.
