# neubird-proxy at MetLife: behind Azure API Management

This guide covers what MetLife sets up to run neubird-proxy: the proxy in MetLife's AKS, an Azure API Management (APIM) API per backend system in front of it, and a NeuBird connection per system.

The proxy needs no outbound connection to NeuBird. It must accept connections only from APIM.

Without APIM, the proxy reaches NeuBird through an outbound tunnel instead: see [tunnel.md](tunnel.md).

| File | What it is |
|---|---|
| [`values.yaml`](values.yaml) | Helm values for the chart's inbound mode |
| [`tunnel.md`](tunnel.md), [`values-tunnel.yaml`](values-tunnel.yaml) | The tunnel path, without APIM |
| [`splunk-policy.xml`](splunk-policy.xml) | APIM policy for the Splunk API |
| [`elastic-policy.xml`](elastic-policy.xml) | APIM policy for the Elasticsearch API |
| [`servicenow-policy.xml`](servicenow-policy.xml) | APIM policy for the ServiceNow API |

Replace every `<...>` and the example hostnames (`*.corp.example`, `example.service-now.com`).

## Credentials

| Credential | Held by | Used for |
|---|---|---|
| APIM subscription key | NeuBird, one key for all systems | NeuBird → APIM |
| Proxy token (64 hex characters) | MetLife: APIM named value **and** a Kubernetes Secret for the proxy | APIM → proxy |
| APIM client certificate | MetLife: uploaded to APIM; its CA goes to the proxy | APIM → proxy (mutual TLS) |
| Each system's credential (Splunk token, ServiceNow account, …) | MetLife, as APIM named values | APIM → proxy → system |
| Proxy TLS certificate | MetLife (internal CA or public) | The proxy's listener |

## Deploy the proxy

Use the Helm chart (`deploy/helm/neubird-proxy`) with `mode: inbound`.

### 1. Secrets

```sh
kubectl create namespace neubird
# The proxy token: the same value goes into APIM's named value neubird-proxy-token.
kubectl -n neubird create secret generic neubird-proxy-env \
  --from-literal=NEUBIRD_PROXY_TOKEN=$(openssl rand -hex 32)
# The listener's certificate, for the name APIM will call.
kubectl -n neubird create secret tls neubird-proxy-tls --cert=tls.crt --key=tls.key
```

Use `--from-literal` as shown, or strip the trailing newline from a file. The proxy trims it, but APIM's named value must match exactly.

### 2. Values

Fill in [`values.yaml`](values.yaml), then:

```sh
helm install neubird-proxy ./neubird-proxy -n neubird -f values.yaml
```

Notes:
- **Methods are shared by every host in `neubird_destinations`.** Restrict paths and methods per system in APIM (see below). `DELETE` is left out on purpose: MCP clients send it to close a session and get a harmless 405.
- **ServiceNow is SaaS**, so its addresses aren't a stable range for `networkPolicy.upstreams`. Allow `example.service-now.com` by name at your egress firewall (Azure Firewall, or an FQDN-aware CNI policy).
- **Behind a load balancer**, `networkPolicy.inboundFrom` sees the address the load balancer forwards from. With the default `externalTrafficPolicy: Cluster`, that's a node's address, so allow the node range as well, or rely on the load balancer's source ranges.
- **Memory limit:** keep the chart's default of 512 Mi or higher; responses are buffered up to `max_body_bytes`.

### 3. Check it

```sh
kubectl -n neubird rollout status deploy/neubird-proxy
kubectl -n neubird logs -l app=neubird-proxy --tail=-1 --prefix | grep -E '"msg":"(starting|risky configuration)"'
```

The `starting` line should show `"tls":true` and `"tunnel":false`. Review each `risky configuration` warning.

## Configure APIM

Create one API per system, with its backend set to `https://<proxy host>/_neubird/dest` and the matching policy file. Its **operations list only the endpoints below**, not `/*`. APIM is the path allowlist; the proxy does not filter paths.

### Named values and certificate

| Name | Secret | Value |
|---|---|---|
| `neubird-proxy-token` | yes | The proxy token, identical to the Kubernetes Secret |
| `splunk-token` | yes | Splunk's token (an MCP token for `/services/mcp`) |
| `servicenow-credential` | yes | ServiceNow's `Authorization` value, e.g. `Basic …` |
| `elastic-api-key` | yes | An Elasticsearch API key (read-only role) |
| Certificate `neubird-proxy-client` | — | APIM's client certificate (PFX), signed by the CA in `inbound.clientCA` |

### Operations

Exactly what NeuBird calls. Anything else, including `DELETE`, `PUT` and `_delete_by_query`, is answered 404 by APIM.

**Splunk** ([`splunk-policy.xml`](splunk-policy.xml): `Bearer` for MCP, `Splunk` for REST, unbuffered MCP streams)

| Method | URL template | Used for |
|---|---|---|
| POST | `/services/mcp` | MCP tools |
| POST | `/services/search/jobs` | Searches (oneshot) |
| GET | `/services/data/indexes` | Index list |
| GET | `/services/server/info` | Connection diagnostics |

The REST calls use `Splunk {{splunk-token}}`, so the token must be valid for Splunk's REST API as well as its MCP server, or use MCP only and drop the REST operations.

**Elasticsearch** ([`elastic-policy.xml`](elastic-policy.xml))

| Method | URL templates |
|---|---|
| GET | `/`, `/_cluster/health`, `/_security/_authenticate`, `/_mapping`, `/{index}/_mapping`, `/_search`, `/{index}/_search` |
| GET | `/_cat/indices`, `/_cat/indices/*`, `/_cat/shards`, `/_cat/shards/*`, `/_data_stream`, `/_data_stream/*` |
| HEAD | `/` |
| POST | `/_search`, `/{index}/_search`, `/_msearch`, `/{index}/_msearch` |

**ServiceNow** ([`servicenow-policy.xml`](servicenow-policy.xml)): the Table API reads NeuBird uses, e.g. `GET /api/now/table/{table}`.

**Writes through MCP.** Read-only operations don't stop writes inside an MCP `POST`: a tool call can carry any SPL. The proxy's `request_deny_patterns` block SPL that writes, sends data or reaches other systems (including `| rest`), and that is the only guard on this path. Extend the patterns if your Splunk has other write commands.

Also on the APIM side (security plan items 9 and 10):
- put the APIs in a product that contains only them;
- add `rate-limit-by-key` or `quota-by-key` on the subscription;
- turn off request tracing;
- add an `ip-filter` for NeuBird's egress addresses.

### Check it

```sh
KEY=<subscription key>
A=https://<apim>.azure-api.net/<splunk api path>
curl -s -o /dev/null -w '%{http_code}\n' -X POST $A/services/mcp              # 401: no key
# 200 and serverInfo: the Splunk token works end to end
curl -s -X POST -H "Ocp-Apim-Subscription-Key: $KEY" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' $A/services/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"check","version":"1"}}}'
```

Don't check with `/services/server/info`: Splunk answers it without a login, so it passes even with a wrong token. For Elastic, `GET $A/_cluster/health` with the key should return the cluster status.

Calls straight to the proxy, not through APIM, must fail at the network or at TLS.

## Connect NeuBird

NeuBird adds one connection per system:
- **URL:** the APIM API's URL:
  - Splunk (MCP): `https://<apim>.azure-api.net/<splunk api path>/services/mcp`;
  - Elasticsearch: the API base only, `https://<apim>.azure-api.net/<elastic api path>`, since NeuBird adds `/_search` and the other paths itself.
- **Credential:** written as `Ocp-Apim-Subscription-Key: <key>`, which NeuBird sends as that header.

The same subscription key works for every API in the product.

## Adding a system

1. Add its host to `neubird_destinations.hosts` (`helm upgrade`).
2. Create its APIM API: read-only operations, the destination, its credential named value, and the same proxy token and client certificate.
3. Add the connection in NeuBird.

No proxy code change is needed. Add deny patterns for the new system's write operations if its API accepts them in request bodies.
