# Rule IDs and Exports

## Why are rule IDs missing in NeuVector ≤ 5.4.6 exports?

In NeuVector versions prior to **5.4.7 (≤ 5.4.6)**, exported Admission Control rules did **not** contain an `ID` field.
When converting, the tool must generate sequential IDs starting from **1000**, which may not match your original rule IDs.

This affects **traceability**: the same rule may appear under a different ID after conversion.


## Example

Say you have a rule with **ID = 1005** in NeuVector.

### Export from ≤ 5.4.6 (ID missing)

```yaml
# NeuVector export (no ID)
apiVersion: neuvector.com/v1
kind: NvAdmissionControlSecurityRule
spec:
  rules:
  - action: deny
    criteria:
    - name: shareIpcWithHost
      op: =
      path: shareIpcWithHost
      value: "true"
    rule_mode: "protect"
```

Converted Kubewarden policy (ID auto-generated, starts at 1000):

```yaml
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: neuvector-rule-1000-conversion
```

### Export from 5.4.7+ (ID preserved)

```yaml
# NeuVector export (note the conversion_id_ref field)
apiVersion: neuvector.com/v1
kind: NvAdmissionControlSecurityRule
spec:
  rules:
  - action: deny
    conversion_id_ref: 1005
    criteria:
    - name: shareIpcWithHost
      op: =
      path: shareIpcWithHost
      value: "true"
    rule_mode: "protect"
```

Converted Kubewarden policy (ID preserved):

```yaml
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: neuvector-rule-1005-conversion
```

In **NeuVector 5.4.7 and later**, rules are exported with the stable field `conversion_id_ref`, so the converter preserves the original IDs.

---

## How does the converter assign IDs when none are present?

If the export has no IDs (≤ 5.4.6), the converter generates IDs **sequentially starting from 1000**.
These generated IDs are internal to the converted policies and may not correspond to the original rule numbering.

---

## How can I preserve my original rule IDs?

To ensure your original IDs are preserved:

1. Export the rules from your current cluster.
2. Import the exported YAML into a NeuVector cluster running **5.4.7 or later**.
3. Export the rules again from that cluster.

The re-exported file will include the correct `conversion_id_ref` values, allowing the converter to maintain the original IDs.
