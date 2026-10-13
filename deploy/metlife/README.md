# neubird-proxy at MetLife: over the NeuBird relay

```
NeuBird ─▶ relay ⇄ tunnel (dialed out by the proxy, :443) ⇄ neubird-proxy (AKS) ─▶ MetLife APIM ─▶ Splunk
```

The proxy runs in MetLife's AKS and opens the tunnel outbound: nothing connects in, and no load balancer or inbound firewall rule is needed. It calls MetLife's APIM with the subscription key from its Secret, checks every request, and redacts every response before it leaves MetLife.

## What NeuBird gives MetLife

| Item | Used as |
|---|---|
| The image, by digest | `image.repository` / `image.digest` (load into your ACR) |
| Relay address and IPs (`<tenant>.tunnel.neubird.ai:443`) | `tunnel.relays`, `networkPolicy.relayCIDRs`, firewall egress |
| Tenant name | `tunnel.tenant` |
| `relay-ca.crt` (public) | `--set-file relayCA.cert=relay-ca.crt` |
| Join token (secret, single use) | `NEUBIRD_JOIN_TOKEN` in the Secret |

MetLife sends nothing back: the proxy enrolls its own key with the join token.

## Deploy

1. **Secret**:
   ```sh
   kubectl create namespace neubird
   kubectl -n neubird create secret generic neubird-proxy-env \
     --from-literal=NEUBIRD_PROXY_TOKEN=$(openssl rand -hex 32) \
     --from-literal=APIM_SUBSCRIPTION_KEY=<key for NeuBird's APIM product> \
     --from-literal=REDACTION_HMAC_KEY=$(openssl rand -hex 32) \
     --from-literal=NEUBIRD_JOIN_TOKEN=<from NeuBird>
   ```
2. **Values**: fill in [`values.yaml`](values.yaml): the image, the relay, the APIM URL for Splunk, the network ranges, and `extraEnv` if internet traffic must use an outbound HTTP proxy (one that inspects TLS breaks the tunnel).
3. **Install**:
   ```sh
   helm install neubird-proxy ./neubird-proxy -n neubird -f values.yaml \
     --set-file relayCA.cert=relay-ca.crt --set-file upstreamCA.cert=metlife-ca.pem
   ```
   `upstreamCA` is the CA that signs `int.apis.metlife.com`; the proxy verifies it.
4. **Check**: pods turn Ready once their tunnels are up.
   ```sh
   kubectl -n neubird logs -l app=neubird-proxy --tail=-1 | grep -E '"msg":"(starting|enrolled with the join token|tunnel connected|risky configuration)"'
   kubectl -n neubird exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml splunk
   ```
   `starting` shows `"tunnel":true`; `test` checks DNS, TCP and TLS to APIM through the `splunk` connection.
5. **Hand NeuBird `NEUBIRD_PROXY_TOKEN`** over a secret channel. NeuBird's Splunk connection reaches `/splunk/services/mcp` through the relay with it.

## Notes

- **Only the listed paths and methods** reach APIM (`connections[].paths`, `methods`); add a path only if NeuBird's connector needs it.
- **Writes through MCP**: `request_deny_patterns` blocks SPL that writes, sends data or reaches other systems (including `| rest`); it's the only guard inside an MCP call.
- **Another system** (ServiceNow, Elastic) is another entry in `connections` with its APIM URL and key header, and its host in `networkPolicy.upstreams`.
- **Cut NeuBird off**: change `NEUBIRD_PROXY_TOKEN` and restart, or scale to 0.
- **Rotate the tunnel key** or the proxy token: see the chart's README (Operate).

An APIM-in-front alternative (NeuBird calls APIM, APIM calls the proxy) is in [`apim/`](apim/README.md).
