# GTI IP Reputation Node

A custom authentication node for PingAM and PingOne Advanced Identity Cloud (PingAIC) that checks the client's IP address against Google Threat Intelligence (VirusTotal) and routes the journey based on the verdict.

## Overview

During authentication, the node reads the client IP from the request, skips private/reserved addresses (which are not in GTI and would waste quota), and looks the IP up against the GTI API. The resulting verdict drives four journey outcomes: `clean`, `suspicious`, `malicious`, or `error`.

Use this node to:

- Block or step-up authentication for requests from IPs with a malicious or suspicious reputation
- Add a risk signal to your journey (via shared state) for downstream nodes or session claims
- Fail open or closed on lookup errors — wiring is up to you

### IP address resolution

The node resolves the client IP in this order:

1. The `X-Real-IP` header (first value, trimmed) — the trusted value set by PingAIC's edge
2. The first entry of `X-Trusted-Forwarded-For` (trimmed, split on commas)

`X-Forwarded-For` is never read.

### Verdict logic

| Condition | Outcome |
|---|---|
| `gti_assessment.verdict` is `MALICIOUS` | `malicious` |
| `gti_assessment.verdict` is `SUSPICIOUS` | `suspicious` |
| `last_analysis_stats.malicious` >= malicious threshold | `malicious` |
| `last_analysis_stats.suspicious` >= suspicious threshold | `suspicious` |
| Otherwise | `clean` |
| Private/reserved address (`10.x`, `127.x`, `169.254.x`, `192.168.x`, `172.16–31.x`, `fe80:`, `::1`, `fc00–fdff:`) | `clean` (no API call; shared state `gtiVerdict=internal`) |

The `gti_assessment` check requires the `x-tool` request header (sent automatically, configurable below); it is optional at runtime — if GTI has not assessed the IP, the verdict falls through to the analysis-stats thresholds.

## Compatibility

| Product | Versions |
|---|---|
| PingAM | 8.0.2 and later |
| PingOne Advanced Identity Cloud | All current tenants |

Built against the PingAM 8.0.2 node SDK (Java 17 bytecode).

## Outcomes

| Outcome | Description |
|---|---|
| `clean` | IP is private/internal, or GTI has no adverse findings |
| `suspicious` | GTI verdict or analysis stats indicate suspicious activity |
| `malicious` | GTI verdict or analysis stats indicate malicious activity |
| `error` | IP unavailable, node not configured, or the lookup failed |

## Configuration

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| API Key | String | Yes | *(empty)* | GTI/VirusTotal API key (`x-apikey`). Free-tier keys allow ~4 requests/minute and ~500/day — add caching or a premium key before production traffic. |
| GTI Base URL | String | No | `https://www.virustotal.com/api/v3/ip_addresses/` | Base URL of the GTI IP address API. |
| Malicious Threshold | Number | No | `2` | `last_analysis_stats.malicious` at or above this value → `malicious`. |
| Suspicious Threshold | Number | No | `5` | `last_analysis_stats.suspicious` at or above this value → `suspicious`. |
| X-Tool | String | No | `ping.aic.gti-ip-node.1.0.0` | Value sent in the `x-tool` header (required by GTI to receive `gti_assessment` data). |

## Shared state

### Reads

| Key | Description |
|---|---|
| *(request headers)* | `X-Real-IP`, then `X-Trusted-Forwarded-For` — see IP resolution above |

### Writes

| Key | Type | When | Description |
|---|---|---|---|
| `gtiVerdict` | String | Successful lookup, or private-IP short-circuit (`internal`) | The resolved verdict: `clean`, `suspicious`, `malicious`, or `internal` |
| `gtiMalicious` | String | Successful lookup | Malicious engine count (as a string) |
| `gtiSuspicious` | String | Successful lookup | Suspicious engine count (as a string) |

Nothing is written on the `error` outcome.

## Error handling

| Condition | Outcome | Failure-node message |
|---|---|---|
| No client IP header present | `error` | `Client IP unavailable` |
| API key not configured | `error` | `Threat intel not configured` |
| Non-2xx API response | `error` | `Threat intel lookup fail` |
| Lookup exception (network, timeout, malformed response) | `error` | `Threat intel lookup unavailable` |

Whether the `error` outcome fails open (continue to `Success`) or fails closed (route to `Failure`) is journey wiring, not node behavior — wire it according to your risk appetite.

## Journey example

```
Start → [Username/Password collection] → [Data Store Decision] → [GTI IP Reputation]
                                                                    ├─ clean      → Success
                                                                    ├─ suspicious → [Step-up auth / MFA]
                                                                    ├─ malicious  → Failure
                                                                    └─ error      → Success or Failure (your policy)
```

To surface the verdict in session claims, map the shared-state keys to session properties downstream of this node.

## Installation

1. Obtain the node jar (`wiz-gti-marketplace-nodes-<version>.jar` — this jar also contains the companion Wiz nodes; see Related nodes).
2. Copy it into `webapps/openam/WEB-INF/lib/` (PingAM) or deploy per your PingAIC packaging process.
3. Restart the AM web application container.
4. The node appears in the journey designer as **Google Threat Intelligence (VirusTotal) IP reputation check**.

## Building from source

Requirements: JDK 17+, Maven 3.8+, and Ping Identity repository credentials (Backstage subscription) configured in `~/.m2/settings.xml` for `https://maven.forgerock.org/artifactory/private-releases`.

```bash
mvn clean package
```

The jar is produced in `target/`.

## Related nodes

- [Wiz Risk Enrichment](https://github.com/ForgeRock/tap-wiz-risk-enrichment)
- [Wiz Cloud Identity Check](https://github.com/ForgeRock/tap-wiz-cloud-identity-check)
- [Wiz Privileged Gate](https://github.com/ForgeRock/tap-wiz-privileged-gate)

## Support

This integration is provided as a sample journey node. Review with your Ping Identity team before production use. For general PingAM/PingAIC node development, see the Ping Identity documentation on custom authentication nodes.
