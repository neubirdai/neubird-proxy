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
| Hostname | `neubird-proxy.htm.neubird.ai`, a Route53 CNAME to the cluster's nginx load balancer |
| Config | `config.yaml` here, as the ConfigMap `neubird-proxy` |
| Secret | `neubird-proxy`: `NEUBIRD_PROXY_TOKEN` and `SPLUNK_MCP_TOKEN`, created by hand |

## NeuBird connection settings

- MCP URL: `https://neubird-proxy.htm.neubird.ai/splunk/services/mcp`
- Bearer token: the proxy token, printed by
  `kubectl --context $CTX -n neubird-proxy-test get secret neubird-proxy -o jsonpath='{.data.NEUBIRD_PROXY_TOKEN}' | base64 -d`

## Operate

```bash
CTX=arn:aws:eks:us-west-2:443370673207:cluster/eks-htm-prod

# Create the Secret once (prompts for the Splunk token, generates the proxy token):
read -rsp 'Splunk MCP token: ' SPLUNK_MCP_TOKEN; echo
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
AWS_PROFILE=hclpoc aws route53 change-resource-record-sets --hosted-zone-id Z0035718E9AOZ22QO38P \
  --change-batch '{"Changes":[{"Action":"DELETE","ResourceRecordSet":{"Name":"neubird-proxy.htm.neubird.ai","Type":"CNAME","TTL":300,"ResourceRecords":[{"Value":"a789033f222a643cab5f7d254316891a-214940763.us-west-2.elb.amazonaws.com"}]}}]}'
AWS_PROFILE=hclpoc aws ecr delete-repository --region us-west-2 --repository-name neubird-proxy --force
```

Then rotate the Splunk MCP token, which was shared in a chat while this was
set up.
