# Getting started examples

The files the [getting started guide](../getting-started.md) uses, so its
commands work as written. All data in them is synthetic.

| File | Used in |
|---|---|
| `config.yaml` | Step 1: the example config, with a Splunk MCP connection and a ServiceNow connection |
| `sample.json` | Step 3: a ServiceNow incident with an email, a phone number, a member ID and a name in free text |
| `incidents.json` | Step 3, HMAC: three incidents, two from the same caller |

```bash
cd docs/examples
np validate -offline -config config.yaml
np preview -config config.yaml -connection servicenow sample.json
```
