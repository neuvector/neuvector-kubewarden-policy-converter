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
NAME:
   nvrules2kw - Convert NeuVector Admission Control Rules to Kubewarden Policies

USAGE:
   nvrules2kw [global options] command [command options] [arguments...]

DESCRIPTION:
   Examples:

   # Fetch NeuVector Admission Control Rules and pipe them to nvrules2kw.
   # For instructions on connecting to the REST API server, visit:
   # https://open-docs.neuvector.com/configuration/console
   curl -k \
     -H "Content-Type: application/json" \
     -H "X-Auth-Apikey: <API_KEY>" \
     "https://<API_SERVER_ADDRESS>/v1/admission/rules" | nvrules2kw --output policies.yaml

   # Convert rules from a file and output to a file
   nvrules2kw convert --rulefile ./rules/nvrules.json --output policies.yaml

   # Show supported criteria
   nvrules2kw support


COMMANDS:
   convert  Convert NeuVector rules to Kubewarden policies
   support  Show supported criteria matrix
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help
```

## Support matrix

You can use the `support` command to view the support matrix.

```
nvrules2kw support
```

The following table shows the support matrix:

```
+--------------------------------------+-----------+------+
|            CRITERION NAME            | SUPPORTED | NOTE |
+--------------------------------------+-----------+------+
| Allow Privilege Escalation           | Yes       |      |
| Annotations                          | Yes       |      |
| Add customized criterion             | No        |      |
| Count of high severity CVE           | No        |      |
| Count of high severity CVE with fix  | No        |      |
| Count of medium severity CVE         | No        |      |
| CVE names                            | No        |      |
| CVE score                            | No        |      |
| Environment variables with secrets   | Yes       |      |
| Environment variables                | Yes       |      |
| Image                                | Yes       |      |
| Image compliance violations          | No        |      |
| Image without OS information         | No        |      |
| Image registry                       | Yes       |      |
| Image scanned                        | No        |      |
| Image signed                         | No        |      |
| Image Sigstore Verifiers             | No        |      |
| Labels                               | Yes       |      |
| Modules                              | No        |      |
| Mount Volumes                        | No        |      |
| Namespace                            | Yes       |      |
| PSP Best Practice                    | Yes       |      |
| Resource Limit Configuration (RLC)   | No        |      |
| Run as privileged                    | Yes       |      |
| Run as root                          | Yes       |      |
| Service Account Bound High Risk Role | No        |      |
| Share host's IPC namespaces          | Yes       |      |
| Share host's Network                 | Yes       |      |
| Share host's PID namespaces          | Yes       |      |
| StorageClass Name                    | No        |      |
| User                                 | Yes       |      |
| User groups                          | Yes       |      |
| Violates PSA policy                  | No        |      |
+--------------------------------------+-----------+------+

```

## Example

You can either pipe in the rules fetched from the NeuVector REST API server or specify them in a file.

```
# Fetch NeuVector Admission Control Rules and pipe them to nvrules2kw.
# For instructions on connecting to the REST API server, visit:
# https://open-docs.neuvector.com/configuration/console
curl -k \
  -H "Content-Type: application/json" \
  -H "X-Auth-Apikey: <API_KEY>" \
  "https://<API_SERVER_ADDRESS>/v1/admission/rules" | nvrules2kw convert --output policies.yaml
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
