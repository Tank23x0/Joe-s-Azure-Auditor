# Security Engineer / Infrastructure Director Mindset (30,000‑ft review)

This guide frames the audit to surface **high‑impact, high‑risk** gaps quickly and communicate them to leadership.

## Priorities (Top‑down)
1. **Identity & Access** (If compromised, everything falls)
2. **Privileged Access Governance** (PIM, JIT, role sprawl)
3. **Security Baseline Drift** (Secure Score, Defender controls)
4. **SharePoint/OneDrive Exposure** (oversharing, anonymous links)
5. **Data Protection & Compliance** (labels, DLP, retention)
6. **Logging & Incident Readiness** (audit log retention, alerting)
7. **Device & Endpoint Integration** (CA + Intune for access control)
8. **Azure Subscription Security** (RBAC, service principals, Defender)
9. **Third‑Party OAuth Risk** (over‑privileged apps)

## Red‑Flag Signals
- Dozens of Global Admins or permanent admin roles
- Legacy auth allowed or weak MFA enforcement
- No PIM for privileged roles
- Anonymous SharePoint/OneDrive links tenant‑wide
- No sensitivity labels or DLP policies
- Unified Audit Log disabled or minimal retention
- Over‑privileged OAuth apps with broad read/write

## Executive Output Style
- **Executive Risk Summary** with Top 10 critical findings
- **Quick Wins (30–60 days)** vs longer‑term roadmap
- Risk maturity labels: Low / Medium / High

## Evidence Expectations
- Prefer **exported evidence** (CSV/JSON/HTML) for defensible audit trail
- Tie findings to **CIS / NIST / ISO** references
- Include raw queries in the Manual Scripts Index
