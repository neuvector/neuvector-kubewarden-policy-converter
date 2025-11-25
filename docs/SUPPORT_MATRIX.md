# Support matrix
This document details the support matrix, including the available operators, accepted values, corresponding Kubewarden modules and settings, as well as any notes.

## Legend
- ✅ **Completed** – All operators/values are supported
- ⚠️ **Partial** – Only partially supported (details should be added in Notes)
- ❌ **Not Support** – Explicitly not supported (detail will be add in the below)
- **TBD** – Module not yet determined

## Summary
| NV Criterion                   |   Status   |        Kubewarden Policy         |
|--------------------------------|:----------:|:----------------------------------:|
| [Add customized criterion](#add-customized-criterion) | ⚠️ Partial | None |
| [Allow privilege escalation](#allow-privilege-escalation) |  ✅ Completed   | `allow-privilege-escalation-psp:v1.0.0` |
| [Annotations](#annotations)    |  ✅ Completed   | `annotations:v0.1.2` |
| [Count high severity CVE](#count-high-severity-cve) |  ✅ Completed   | `image-cve-policy:v0.5.0` |
| [Count high severity CVE with fix](#count-high-severity-cve-with-fix) |          |                                    |
| [Count medium severity CVE](#count-medium-severity-cve) |  ✅ Completed   | `image-cve-policy:v0.5.0` |
| [CVE names](#cve-names)        |            |                                    |
| [CVE score](#cve-score)        |  ❌ Not Support  |                                    |
| [Environment variables with secrets](#environment-variables-with-secrets) |  ⚠️ Partial   | `env-variable-secrets-scanner:v1.0.5` |
| [Environment variables](#environment-variables) |  ✅ Completed   | `environment-variable-policy:v3.0.2` |
| [Image](#image)                |  ✅ Completed   | `trusted-repos:v2.0.1` |
| [Image compliance violations](#image-compliance-violations) |            |                                    |
| [Image without OS information](#image-without-os-information) | ❌ Not Support |                                    |
| [Image registry](#image-registry) |  ✅ Completed   | `trusted-repos:v2.0.1` |
| [Image scanned](#image-scanned) | ✅ Completed | `image-cve-policy:v0.5.0` |
| [Image signed](#image-signed)  |            |                                    |
| [Image sigstore verifiers](#image-sigstore-verifiers) | ❌ Not Support |                                    |
| [Labels](#labels)              |  ✅ Completed   | `labels:v0.1.2` |
| [Modules](#modules)            |  ❌ Not Support  |                                    |
| [Mount Volumes](#mount-volumes) |            |                                    |
| [Namespace](#namespace)        |  ✅ Completed   | `cel-policy:v1.3.4` |
| [PSP best practice](#psp-best-practice) |     ✅ Completed       | `allow-privilege-escalation-psp:v1.0.0`, `container-running-as-user:v1.0.4`, `host-namespaces-psp:v1.1.0`, `pod-privileged:v1.0.3` |
| [Resource Limit Configuration](#resource-limit-configuration) |            |                                    |
| [Run as privileged](#run-as-privileged) |  ✅ Completed   | `pod-privileged:v1.0.3`            |
| [Run as root](#run-as-root)    |  ✅ Completed   | `container-running-as-user:v1.0.4` |
| [Service Account Bound high risk role](#service-account-bound-high-risk-role) | ✅ Completed | `high-risk-service-account:v0.1.2` |
| [Share host IPC namespaces](#share-host-ip-namespaces) |  ✅ Completed   | `host-namespaces-psp:v1.1.0`       |
| [Share host network](#share-host-network) |  ✅ Completed   | `host-namespaces-psp:v1.1.0`       |
| [Share host PID namespace](#share-host-pid-namespace) |  ✅ Completed   | `host-namespaces-psp:v1.1.0`       |
| [StorageClass Name](#storageclass-name) | ⚠️ Partial  | `persistentvolumeclaim-storageclass-policy:v1.1.0` |
| [User](#user)                  |            |                                    |
| [User groups](#user-groups)    |            |                                    |
| [Violate PSA policy](#violate-psa-policy) | ❌ Not Support |                                    |




---
## Add customized criterion

**Status:** ⚠️ Partial | **Kubewarden Module:** None

**Note**: We currently support generating the Rego policy for you. Once it has been generated, follow the steps below to turn it into a valid Kubewarden policy. For further details, see the Distributing an OPA policy with Kubewarden guide: https://docs.kubewarden.io/tutorials/writing-policies/rego/open-policy-agent/distribute

1. Locate the Rego policy file, usually under `rego_policies/nv_rule_ID.rego`.
2. Clone the [opa-policy-template](https://github.com/kubewarden/opa-policy-template) repository, then copy the contents of `rego_policies/nv_rule_ID.rego` into `opa-policy-template/policy.rego`.
3. In the `opa-policy-template` directory, run the following commands:
   1. `OPA_V0_COMPATIBLE=true make policy.wasm` to generate `policy.wasm`.
   2. `make annotated-policy.wasm` to annotate the module with Kubewarden metadata so it can be used by the PolicyServer.
4. Push the annotated policy to your registry, for example:
   `kwctl push annotated-policy.wasm registry://ghcr.io/{your}/policies/custom:v0.1.0`

Apply a ClusterAdmissionPolicy similar to the template below.
For example, if you want to use this custom policy for resources like Deployments and ReplicaSets:

```bash
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: {policy name}
spec:
  backgroundAudit: true
  mode: protect
  module: registry://ghcr.io/{your}/policies/custom:v0.1.0
  mutating: false
  policyServer: default
  namespaceSelector:
    matchExpressions:
    - key: metadata.namespace
      operator: NotIn / In
      values:
      - foo
      - bar
  rules:
  - apiGroups:
    - apps
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - deployments
    - replicasets
    - daemonsets
    - statefulsets
  settings: {}

```

With these steps, you end up with a working Kubewarden policy that enforces your custom rule.

---

## Allow privilege escalation

**Status:** ✅ Completed | **Kubewarden Module:** `allow-privilege-escalation-psp:v1.0.0`

| Operator | Values | Notes |
| -------- | ------ | ----- |
| `=`      | `true` |       |

---

## Annotations

**Status:** ✅ Completed | **Kubewarden Module:** `annotations:v0.1.2`

| Operator            | Values | Notes |
| ------------------- | ------ | ----- |
| `containsAll`       |   annotations    |       |
| `containsAny`       |   annotations    |       |
| `notContainsAny`    |   annotations    |       |
| `containsOtherThan` |   annotations    |       |

---

## Count high severity CVE

**Status:** ✅ Completed  | **Kubewarden Module:** `image-cve-policy:v0.5.0`

| Operator | Values | Notes |
| -------- | ------ | ----- |
| `>=`     |        |       |


**Sub-option: publishDays** ❌ Not Support

**Note:** Every CVE is in scope and must not be ignored, regardless of how long ago it was published.

---

## Count high severity CVE with fix

**Status:** ✅ Completed  | **Kubewarden Module:**

| Operator | Values | Notes |
| -------- | ------ | ----- |
| `>=`     |        |       |

**Sub-option: publishDays**

| Operator | Values | Notes |
| -------- | ------ | ----- |
| `>=`     |        |       |

---

## Count medium severity CVE

**Status:** ✅ Completed  | **Kubewarden Module:** `image-cve-policy:v0.5.0`

| Operator | Values | Notes |
| -------- | ------ | ----- |
| `>=`     |        |       |

**Sub-option: publishDays** ❌ Not Support

**Note:** Every CVE is in scope and must not be ignored, regardless of how long ago it was published.

---

## CVE names

**Status:** TBD | **Kubewarden Module:**

| Operator            | Values | Notes |
| ------------------- | ------ | ----- |
| `containsAll`       |        |       |
| `containsAny`       |        |       |
| `notContainsAny`    |        |       |
| `containsOtherThan` |        |       |

---

## CVE score

**Status:** ❌ Not Support

**Note**: Current critical/high/medium settings should be enough, postpone this until we have some actual requests

| Operator | Values | Notes |
| -------- | ------ | ----- |
| `>=`     |        |       |

**Sub-option: count**

| Operator | Values | Notes |
| -------- | ------ | ----- |
| `>=`     |        |       |

---

## Environment variables with secrets

**Status:** ✅ Completed | **Kubewarden Module:** `env-variable-secrets-scanner:v1.0.5`

**Note:** `envVarSecrets` supports only false; any other value fails.

| Operator | Values          | Notes |
| -------- | --------------- | ----- |
| `=`      | `true`, `false` |       |

---

## Environment variables

**Status:** ✅ Completed | **Kubewarden Module:** `environment-variable-policy:v3.0.2`

| Operator            | Values | Notes |
| ------------------- | ------ | ----- |
| `containsAll`       |   environment var key     |       |
| `containsAny`       |   environment var key     |       |
| `notContainsAny`    |   environment var key     |       |
| `containsOtherThan` |   environment var key     |       |

---

## Image

**Status:** ✅ Completed | **Kubewarden Module:**  `trusted-repos:v2.0.1`

| Operator         | Values | Notes |
| ---------------- | ------ | ----- |
| `containsAny`    |   image name     |       |
| `notContainsAny` |   image name     |       |

---

## Image compliance violations

**Status:** TBD | **Kubewarden Module:**

| Operator | Values          | Notes |
| -------- | --------------- | ----- |
| `=`      | `true`, `false` |       |

---

## Image without OS information

**Status:** ❌ Not Support

**Note:** NeuVector checks only for the presence of OS info, offering no security benefit. Migration will occur if requested.
---

## Image registry

**Status:** ✅ Completed | **Kubewarden Module:**  `trusted-repos:v2.0.1`

| Operator         | Values | Notes |
| ---------------- | ------ | ----- |
| `containsAny`    |   registry name list   |       |
| `notContainsAny` |   registry name list   |       |

---

## Image scanned

**Status:** ✅ Completed | **Kubewarden Module:** `image-cve-policy:v0.5.0`


**Note:** In NeuVector, setting image scanned to true allows not scanned images to deploy. Set `ignoreMissingVulnerabilityReport` to  true to have the same behavior. By default, not scanned images are rejected.

| Operator | Values          | Notes |
| -------- | --------------- | ----- |
| `=`      | `true`, `false` |       |
---

## Image signed

**Status:** TBD | **Kubewarden Module:**

| Operator | Values          | Notes |
| -------- | --------------- | ----- |
| `=`      | `true`, `false` |       |

---

## Image sigstore verifiers

**Status:** ❌ Not Support

**Note:** This is neuvector native feature, will not support in the future.


---

## Labels

**Status:** ✅ Completed | **Kubewarden Module:** `labels:v0.1.2`

| Operator            | Values | Notes |
| ------------------- | ------ | ----- |
| `containsAll`       |  label   |       |
| `containsAny`       |  label   |       |
| `notContainsAny`    |  label   |       |
| `containsOtherThan` |  label   |       |

---

## Modules

**Status:** ❌ Not Support

**Note**: Postpone this until we have some actual requests

| Operator            | Values | Notes |
| ------------------- | ------ | ----- |
| `containsAll`       |        |       |
| `containsAny`       |        |       |
| `notContainsAny`    |        |       |
| `containsOtherThan` |        |       |

---

## Mount Volumes

**Status:** TBD | **Kubewarden Module:**

| Operator            | Values | Notes |
| ------------------- | ------ | ----- |
| `containsAll`       |        |       |
| `containsAny`       |        |       |
| `notContainsAny`    |        |       |
| `containsOtherThan` |        |       |

---

## Namespace

**Status:** ✅ Completed | **Kubewarden Module:** `cel-policy:v1.3.4`

| Operator         | Values | Notes |
| ---------------- | ------ | ----- |
| `containsAny`    |   namespace    |       |
| `notContainsAny` |   namespace    |       |

---

## PSP best practice
**Status:** ✅ Completed

**Kubewarden Module:**
- allow-privilege-escalation-psp:v1.0.0
- container-running-as-user:v1.0.4
- host-namespaces-psp:v1.1.0
- pod-privileged:v1.0.3

| Operator | Values | Notes |
| -------- | ------ | ----- |
| `=`      | `true` |       |

---

## Resource Limit Configuration

**Status:** TBD | **Kubewarden Module:**

| Operator | Values | Notes |
| -------- | ------ | ----- |
| *(none)* |        |       |

**Sub-options:**

* cpuLimit

  | Operator | Values | Notes |
  | -------- | ------ | ----- |
  | `>`      |        |       |
  | `<=`     |        |       |

* cpuRequest

  | Operator | Values | Notes |
  | -------- | ------ | ----- |
  | `>`      |        |       |
  | `<=`     |        |       |

* memoryLimit

  | Operator | Values | Notes |
  | -------- | ------ | ----- |
  | `>`      |        |       |
  | `<=`     |        |       |

* memoryRequest

  | Operator | Values | Notes |
  | -------- | ------ | ----- |
  | `>`      |        |       |
  | `<=`     |        |       |

---

## Run as privileged

**Status:** ✅ Completed | **Kubewarden Module:** `pod-privileged:v1.0.3`

| Operator | Values          | Notes |
| -------- | --------------- | ----- |
| `=`      | `true`, `false` |       |

---

## Run as root

**Status:** ✅ Completed | **Kubewarden Module:** `container-running-as-user:v1.0.4`

| Operator | Values          | Notes |
| -------- | --------------- | ----- |
| `=`      | `true`, `false` |       |

---

## Service Account Bound high risk role

**Status:** ✅ Completed Support | **Kubewarden Module:** `high-risk-service-account:v0.1.2`

| Operator         | Values | Notes |
| ---------------- | ------ | ----- |
| `containsTagAny` |    `risky_role_create_pod`,`risky_role_exec_into_container`,`risky_role_view_secret`,`risky_role_any_action_workload`,`risky_role_any_action_rbac`    |       |


---

## Share host IPC namespaces

**Status:** ✅ Completed Support | **Kubewarden Module:** `allow-privilege-escalation-psp:v1.0.0`

| Operator | Values          | Notes |
| -------- | --------------- | ----- |
| `=`      | `true`, `false` |       |

---

## Share host network

**Status:** ✅ Completed Support | **Kubewarden Module:** `allow-privilege-escalation-psp:v1.0.0`

| Operator | Values          | Notes |
| -------- | --------------- | ----- |
| `=`      | `true`, `false` |       |

---

## Share host PID namespace

**Status:** ✅ Completed Support | **Kubewarden Module:** `allow-privilege-escalation-psp:v1.0.0`

| Operator | Values          | Notes |
| -------- | --------------- | ----- |
| `=`      | `true`, `false` |       |

---

## StorageClass Name

**Status:** ⚠️ Partial | **Kubewarden Module:** `persistentvolumeclaim-storageclass-policy:v1.1.0`

**Note:** Currently, the policy can only block PVCs created with specific StorageClass names. It cannot prevent workloads from using existing PVCs that reference those StorageClasses

| Operator         | Values | Notes |
| ---------------- | ------ | ----- |
| `containsAny`    |   Storage Class name list, e.g. foo,bar    |       |
| `notContainsAny` |   Storage Class name list, e.g. foo,bar     |       |

---

## User

**Status:** TBD | **Kubewarden Module:**

| Operator         | Values | Notes |
| ---------------- | ------ | ----- |
| `containsAny`    |        |       |
| `notContainsAny` |        |       |
| `regex`          |        |       |
| `!regex`         |        |       |

---

## User groups

**Status:** TBD | **Kubewarden Module:**

| Operator            | Values | Notes |
| ------------------- | ------ | ----- |
| `containsAll`       |        |       |
| `containsAny`       |        |       |
| `notContainsAny`    |        |       |
| `containsOtherThan` |        |       |
| `regex`             |        |       |
| `!regex`            |        |       |

---

## Violate PSA policy

**Status:** ❌ Not Support

**Note:** We do not provide direct enforcement for PSA (Pod Security Admission) violations through this converter.
Instead, please rely on the native Pod Security Admission mechanisms available in Kubernetes, specifically the audit or warn modes.
