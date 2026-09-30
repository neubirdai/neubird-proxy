# Test deployment on eks-htm-prod

The proxy in front of the Splunk E2E instance's MCP server, for end-to-end
testing from the NeuBird platform. This is not a MetLife deployment: there is
no APIM, and the proxy injects the Splunk MCP token itself. For MetLife, see
`deploy/kubernetes.yaml` and `deploy/config.example.yaml`.

```
NeuBird ──(proxy token)──▶ https://neubird-proxy.htm.neubird.ai/splunk/services/mcp
          ingress-nginx (TLS, Let's Encrypt) ──▶ neubird-proxy (2 pods)
          ──(Splunk MCP token)──▶ https://splunk-e2e.tools.neubird.ai/services/mcp
```

| What | Where |
|---|---|
| Cluster | `eks-htm-prod`, us-west-2, account 443370673207 (AWS profile `hclpoc`) |
| Namespace | `neubird-proxy-test` |
| Image | ECR `neubird-proxy` in that account, tags immutable, scanned on push, deployed by digest |
| Hostname | `neubird-proxy.htm.neubird.ai`, a Route53 CNAME to the cluster's nginx load balancer. The zone that serves `htm.neubird.ai` is in account 810918113647 (profile `neubird`), not the cluster's account, which has an unused zone of the same name |
| Config | `config.yaml` here, as the ConfigMap `neubird-proxy` |
| Secret | `neubird-proxy`: `NEUBIRD_PROXY_TOKEN` and `SPLUNK_MCP_TOKEN`, created by hand |

## NeuBird connection settings

- MCP URL: `https://neubird-proxy.htm.neubird.ai/splunk/services/mcp`
- Bearer token: the proxy token, printed by
  `kubectl --context $CTX -n neubird-proxy-test get secret neubird-proxy -o jsonpath='{.data.NEUBIRD_PROXY_TOKEN}' | base64 -d`

## Known limits of this environment

- **Client IPs.** Audit lines record the load balancer's private address as
  `forwarded_for`, not the caller's IP: the cluster's classic ELB does not
  pass it through (no proxy protocol on ingress-nginx). Fixing that is a
  cluster-wide ingress change, out of scope for this namespace.
- **No ServiceNow yet.** The developer instance given for the test no longer
  exists; add a `servicenow` connection once there is a live one.

## Operate

```bash
CTX=arn:aws:eks:us-west-2:443370673207:cluster/eks-htm-prod

# Create the Secret once (prompts for the Splunk token, generates the proxy token):
# (printf + read -rs works in both zsh and bash; zsh's read -p does not prompt)
printf 'Splunk MCP token: '; read -rs SPLUNK_MCP_TOKEN; echo; echo "read ${#SPLUNK_MCP_TOKEN} characters"
kubectl --context $CTX -n neubird-proxy-test create secret generic neubird-proxy \
  --from-literal=NEUBIRD_PROXY_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=SPLUNK_MCP_TOKEN="$SPLUNK_MCP_TOKEN"
unset SPLUNK_MCP_TOKEN

deploy/test-eks/deploy.sh               # build, push, apply, restart
SKIP_BUILD=1 deploy/test-eks/deploy.sh  # config or manifest change only

# Audit lines (one per request) and startup warnings:
kubectl --context $CTX -n neubird-proxy-test logs -l app=neubird-proxy --tail=50 -f
```

## Tear down

```bash
kubectl --context $CTX delete namespace neubird-proxy-test
AWS_PROFILE=neubird aws route53 change-resource-record-sets --hosted-zone-id Z09670351IMMSN9X6HXH3 \
  --change-batch '{"Changes":[{"Action":"DELETE","ResourceRecordSet":{"Name":"neubird-proxy.htm.neubird.ai","Type":"CNAME","TTL":300,"ResourceRecords":[{"Value":"a789033f222a643cab5f7d254316891a-214940763.us-west-2.elb.amazonaws.com"}]}}]}'
AWS_PROFILE=hclpoc aws ecr delete-repository --region us-west-2 --repository-name neubird-proxy --force
```

Then rotate the Splunk MCP token, which was shared in a chat while this was
set up.
