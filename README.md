# nvrules2kw

**nvrules2kw** is a CLI tool that converts [NeuVector](https://open-docs.neuvector.com/policy/admission) Admission Control Rules into [Kubewarden](https://www.kubewarden.io/) [Policy Custom Resources](https://docs.kubewarden.io/reference/CRDs).

This tool simplifies the migration from NeuVector's admission control model to [Kubewarden](https://kubewarden.io/) — a universal policy engine for Kubernetes that streamlines the adoption of policy-as-code practices.

## Features

- Parse NeuVector admission control rules (exported via `/v1/admission/rules` API)
- Generate equivalent Kubewarden `ClusterAdmissionPolicy` or `ClusterAdmissionPolicyGroup` resources
- Supports output to stdout or to a file
- Bind the generated policy to a specified Policy Server
- Optionally enable audit/background enforcement
- Display a summary table showing the status of each rule conversion

## Installation

Download the latest release binary from the [Releases](#) page (link to be added).

Or, if you are developing locally:

```bash
go build -o nvrules2kw
```

## Usage

```
nvrules2kw --rulefile <rules.json> [flags]
```

## Flags

| Flag               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `--rulefile`       | **(Required)** Path to the NeuVector rules JSON file. This file should be the output from NeuVector’s `/v1/admission/rules` API. |
| `--policyserver`   | Name of the Kubewarden Policy Server to bind the generated policy to. Default is `"default"`. |
| `--backgroundaudit`| Whether to enable the policy in background audit checks. Default is `false`. |
| `--output`         | Path to write the generated Kubewarden policy YAML. If not specified, output is printed to `stdout`. |


## Example

```
nvrules2kw \
  --rulefile ./sample_rules.json \
  --policyserver edge-policy-server \
  --output generated_policy.yaml

```

A summary table will be displayed to show the status of each rule conversion.

```
+------+--------+---------------------------------+
|  ID  | STATUS |              NOTES              |
+------+--------+---------------------------------+
|    1 | Skip   | NeuVector environment only rule |
|    2 | Skip   | NeuVector environment only rule |
| 1000 | Skip   | Unsupported criteria            |
| 1001 | Ok     | Rule converted successfully     |
| 1002 | Ok     | Rule converted successfully     |
| 1005 | Ok     | Rule converted successfully     |
| 1006 | Ok     | Rule converted successfully     |
| 1007 | Ok     | Rule converted successfully     |
| 1008 | Ok     | Rule converted successfully     |
| 1009 | Ok     | Unsupported criteria            |
+------+--------+---------------------------------+
```