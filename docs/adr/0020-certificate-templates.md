# ADR-0020: Certificate templates

**Status:** Accepted (2026-11-21)

## Context
Every deployment today carries its own issuer, challenge type, key algorithm and names.
With more than a handful of deployments, teams want what CLM products call issuing
templates or certificate profiles: an approved recipe (which CA, which key, which
names) that requesters pick instead of filling in details, and that platform teams
change in one place.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Deployments reference a template; changes apply to every deployment using it** | One place to change a CA or key type; matches Venafi, DigiCert, Keyfactor; ADR-0015 already turns a changed effective spec into a re-approval | A bad template change touches many deployments at once (mitigated by plan/apply below) |
| B. Template copied into the deployment at creation | Simple; no fleet-wide effect | Deployments drift from the template; changing a CA means editing every deployment |

SAN constraints:
| Option | For | Against |
|---|---|---|
| **Glob patterns** (`*.example.com`, `api-*.corp.example.com`) | Same model as the agent's `allowed_sans`; hard to write too broadly; no regex denial of service | Less expressive than regex |
| Regular expressions (Venafi, Keyfactor) | Very expressive | Easy to write too broadly (unanchored, `.` for a dot) |

## Decision
Option A with glob patterns.

**Template document** (versioned YAML, applied with plan/apply like policy):

```yaml
apiVersion: certloom/v1
kind: CertificateTemplate
metadata:
  name: public-web
spec:
  issuer: le-production          # issuer name
  challenge: http-01             # or dns-01
  keyAlgorithms: [ecdsa-p256]    # allowed; the first is the default
  sans:
    allowed: ["*.example.com", "example.com"]
    maxNames: 10
    wildcards: false             # whether *.name may be requested
  maintenanceWindow: ""          # default window for new deployments (ADR-0013)
```

- In patterns, `*` matches one or more characters within a single DNS label. Matching is
  case-insensitive and ignores a trailing dot. A requested wildcard name (`*.example.com`)
  needs `wildcards: true` and must itself match a pattern. Patterns are checked when the
  template is applied (valid DNS shape, at most one `*` per label, no bare `*`).
- Each apply stores a new version with its source. A template is deleted only when no
  deployment uses it.

**Deployments**
- `certloom deployment create --template public-web --lineage ... --agent ... --target ...
  --san ...`. Issuer, challenge and key algorithm come from the template. A deployment
  may still set a key algorithm the template allows; it may not set a different issuer
  or challenge.
- The deployment stores the template id and the resolved values. Approvals keep
  covering the resolved effective spec (ADR-0015); the template name and version are
  not part of the digest, so a template change that resolves to the same spec needs no
  re-approval.
- Policy `templates.required: true` makes every new deployment use a template.

**Applying a changed template**
- The plan lists the deployments it changes (issuer, challenge, key algorithm), which of
  them will need a new approval, and the ones that would break the new constraints (a
  name no longer allowed, too many names, a key algorithm no longer listed).
- Apply refuses while any deployment would break the constraints: the template or the
  deployments are fixed first. Otherwise it updates every deployment in the same
  transaction as the new version and audits each change.

**Permissions**
- New `templates:manage` for owner and `issuer_admin`. Everyone with inventory read
  access can list and show templates.

## Industry practice (surveyed 2026-11-21)
| Who | Approach |
|---|---|
| [Venafi / CyberArk issuing templates](https://docs.paloaltonetworks.com/next-gen-trust-security/next-gen-trust-security/about-vaas/co-overview-issuing-certs/certificate-issuing-templates/creating-a-certificate-issuing-template) ([regex rules](https://docs.paloaltonetworks.com/content/techdocs/en_US/next-gen-trust-security/next-gen-trust-security/about-vaas/co-overview-issuing-certs/certificate-issuing-templates/c-templates-using-advanced-rules-regex.html)) | CA, key generation, EKU, validity, CN/SAN regular expressions; templates assigned to applications and used for requests |
| [DigiCert Trust Lifecycle Manager](https://docs.digicert.com/en/trust-lifecycle-manager/certificate-profiles.html) ([wizard](https://docs.digicert.com/en/trust-lifecycle-manager/certificate-profiles/create-certificate-profiles/use-the-profile-configuration-wizard.html)) | Certificate profiles: issuing CA, enrollment method, algorithm and key size, validity, subject and SAN fields, renewal; enrollments use the profile |
| [Keyfactor Command](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/TemplatesGETSettings.htm) | Templates with per-field regular expressions and allowed RSA sizes and ECC curves |
| [Sectigo Certificate Manager](https://docs.sectigo.com/scm/scm-administrator/managing-certificate-profiles.html) | Certificate profiles per organization |
| cert-manager approver-policy | Glob-style allowed values for names in a request policy (not re-checked against current docs in this survey) |

Commercial CLM products agree on named, referenced profiles that fix the CA and key
type and constrain the names. Most use regular expressions for names; this decision uses
glob patterns instead, the same model the agent already enforces, because they are
harder to get dangerously wrong.

## Consequences
- One template change can move many deployments to a new CA or key type; the plan shows
  which, and approvals stop runs until the new spec is approved where approvals are
  required.
- Templates do not yet set validity: ACME CAs decide lifetimes through profiles, which
  live on the issuer. Validity and EKU arrive with private CA issuers (M7).

## Verification
- Unit: glob matching (labels, case, trailing dot, wildcards), document validation.
- Workflow: create with a template; constraint violations refused; plan lists changed
  deployments and re-approvals; apply refused on breaking changes; apply updates
  deployments and voids approvals of changed specs only; `templates.required`; delete
  refused while in use.

## As built (2026-11-21)
- Migration 00010: `templates` (current version), `template_versions` (document and
  source per version), `deployments.template_id`. Applies of one template name are
  serialized with an advisory lock.
- A deployment created from a template stores the resolved issuer, challenge and key
  algorithm; the template's maintenance window is the default when none is given.
- On apply, a deployment whose spec was approved gets the new digest at once when the
  person applying may manage deployments and approvals are optional; otherwise its open
  requests are closed as superseded and a new request is opened by the person applying,
  so someone else decides it. Denied and revoked deployments only get the new values.
- The apply does not check that agents of a template switched to DNS-01 have solvers;
  their next run fails with the usual "no dns solver" error.
