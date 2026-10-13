# neubird-proxy at MetLife: behind Azure API Management

This guide covers what MetLife sets up to run neubird-proxy: the proxy in MetLife's AKS, an Azure API Management (APIM) API per backend system in front of it, and a NeuBird connection per system.

The proxy needs no outbound connection to NeuBird. It must accept connections only from APIM.

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

```yaml
image:
  repository: <your-acr>.azurecr.io/neubird/neubird-proxy
  digest: sha256:<from NeuBird's release notes>
replicaCount: 2
mode: inbound
inbound:
  tls:
    existingSecret: neubird-proxy-tls
  clientCA:
    cert: |                       # the CA that signed APIM's client certificate
      -----BEGIN CERTIFICATE-----
      ...
  service:
    type: LoadBalancer
    port: 443
    annotations:
      # APIM inside your VNet: an internal load balancer.
      service.beta.kubernetes.io/azure-load-balancer-internal: "true"
    # APIM outside your VNet: a public load balancer limited to APIM's addresses.
    # loadBalancerSourceRanges: ["<APIM public IP>/32"]
# MetLife's internal CA bundle: the proxy verifies every backend's certificate,
# and each backend's certificate must name the host listed in hosts below.
upstreamCA:
  cert: |
    -----BEGIN CERTIFICATE-----
    ...
env:
  existingSecret: neubird-proxy-env
config:
  client_token_env: NEUBIRD_PROXY_TOKEN
  max_body_bytes: 20971520
  neubird_destinations:
    hosts:                        # the only systems the proxy will call
      - splunk.corp.example:8089
      - elastic.corp.example:9200
      - example.service-now.com
    methods: [GET, HEAD, POST]
    client_auth: header
    client_auth_header: X-Neubird-Proxy-Token
    request_deny_patterns:
      - "(?i)\\|\\s*(sendemail|sendalert|outputlookup|outputcsv|outputtext|collect|mcollect|meventcollect|tscollect|delete|script|run|runshellscript|map|dbxoutput|dbxquery|sendresults)\\b"
    rate_limit: {requests_per_second: 10, burst: 30}
  redaction:
    mask: label                   # or hmac, with REDACTION_HMAC_KEY in the Secret
networkPolicy:
  enabled: true
  inboundFrom: [{ipBlock: {cidr: <APIM subnet or IP>}}]
  upstreams:
    - {cidr: <Splunk range>, ports: [8089]}
    - {cidr: <Elastic range>, ports: [9200]}
```

```sh
helm install neubird-proxy ./neubird-proxy -n neubird -f metlife-values.yaml
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

Create one API per system. Each API's backend is the proxy, and its **operations list only the read endpoints NeuBird needs**, not `/*`. APIM is the path allowlist; the proxy does not filter paths.

### Named values and certificate

| Name | Secret | Value |
|---|---|---|
| `neubird-proxy-token` | yes | The proxy token, identical to the Kubernetes Secret |
| `splunk-token` | yes | Splunk's token (an MCP token for `/services/mcp`) |
| `servicenow-credential` | yes | ServiceNow's `Authorization` value, e.g. `Basic …` |
| `elastic-api-key` | yes | An Elasticsearch API key (read-only role) |
| Certificate `neubird-proxy-client` | — | APIM's client certificate (PFX), signed by the CA in `inbound.clientCA` |

### Splunk API policy

```xml
<policies>
  <inbound>
    <base />
    <set-header name="Ocp-Apim-Subscription-Key" exists-action="delete" />
    <set-header name="Authorization" exists-action="delete" />
    <!-- Splunk's REST API takes "Splunk <token>"; its MCP server takes "Bearer <token>". -->
    <choose>
      <when condition="@(context.Request.OriginalUrl.Path.Contains(&quot;/services/mcp&quot;))">
        <set-header name="X-Neubird-Upstream-Authorization" exists-action="override">
          <value>Bearer {{splunk-token}}</value>
        </set-header>
      </when>
      <otherwise>
        <set-header name="X-Neubird-Upstream-Authorization" exists-action="override">
          <value>Splunk {{splunk-token}}</value>
        </set-header>
      </otherwise>
    </choose>
    <set-header name="X-Neubird-Destination" exists-action="override">
      <value>https://splunk.corp.example:8089</value>
    </set-header>
    <set-header name="X-Neubird-Proxy-Token" exists-action="override">
      <value>{{neubird-proxy-token}}</value>
    </set-header>
    <authentication-certificate certificate-id="neubird-proxy-client" />
  </inbound>
  <backend>
    <!-- MCP responses stream (SSE): don't buffer them. -->
    <forward-request buffer-response="false" timeout="300" />
  </backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
```

- **Backend URL:** `https://<proxy host>/_neubird/dest`.
- **Operations** (exactly what NeuBird calls):

  | Method | URL template | Used for |
  |---|---|---|
  | POST | `/services/mcp` | MCP tools |
  | POST | `/services/search/jobs` | Searches (oneshot) |
  | GET | `/services/data/indexes` | Index list |
  | GET | `/services/server/info` | Connection diagnostics |

  The REST calls use `Splunk {{splunk-token}}`, so the token must be valid for Splunk's REST API as well as its MCP server, or use MCP only and drop the REST operations.
- **ServiceNow:** the same policy, with `X-Neubird-Destination: https://example.service-now.com`, the credential `{{servicenow-credential}}` (no scheme switch), and operations such as `GET /api/now/table/{table}`.

### Elastic API

The same policy as Splunk, with no scheme switch, a 120-second timeout and buffered responses:

```xml
<set-header name="X-Neubird-Upstream-Authorization" exists-action="override">
  <value>ApiKey {{elastic-api-key}}</value>
</set-header>
<set-header name="X-Neubird-Destination" exists-action="override">
  <value>https://elastic.corp.example:9200</value>
</set-header>
```

Operations (exactly what NeuBird calls):

| Method | URL templates |
|---|---|
| GET | `/`, `/_cluster/health`, `/_security/_authenticate`, `/_mapping`, `/{index}/_mapping`, `/_search`, `/{index}/_search` |
| GET | `/_cat/indices`, `/_cat/indices/*`, `/_cat/shards`, `/_cat/shards/*`, `/_data_stream`, `/_data_stream/*` |
| HEAD | `/` |
| POST | `/_search`, `/{index}/_search`, `/_msearch`, `/{index}/_msearch` |

Anything else, including `DELETE`, `PUT` and `_delete_by_query`, is answered 404 by APIM.

**Writes through MCP.** Read-only operations don't stop writes inside an MCP `POST`: a tool call can carry any SPL. The proxy's `request_deny_patterns` block SPL that writes or sends data, and that is the only guard on this path. Extend the patterns if your Splunk has other write commands.

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
