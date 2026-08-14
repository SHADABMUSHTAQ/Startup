# WarSOC Documentation Index

**Current as of:** 2026-08-13

Use these documents as the production source of truth:

1. `WARSOC_FRONTEND_PRODUCT_AND_DESIGN_HANDOFF_2026-08-13.md`
   - Authoritative customer-facing route, role, state, workflow, privacy and
     gated-module map for frontend design and implementation.
2. `WARSOC_CURRENT_IMPLEMENTATION_AND_FUTURE_SCOPE.md`
   - Consolidated status register separating the active product, source-proven
     candidates, lab-only proof, deployment gates, future phases, and explicit
     exclusions.
3. `WARSOC_BUILD_VALIDATE_FREEZE_EXECUTION_PLAN.md`
   - Approved scope-freeze, reproducible-candidate, validation, pentest, and
     production-freeze sequence.
4. `WARSOC_CURRENT_STATE_ARCHITECTURE.md`
   - Detailed as-built architecture, pipeline contracts, retention behavior,
     production proof, and remaining controlled-pilot obligations.
5. `WARSOC_WAZUH_FIREWALL_IMPLEMENTATION_LEDGER_2026-08-13.md`
   - Phase-by-phase Wazuh and firewall implementation truth: completed code and
     labs, failure boundaries, production-disabled state, and exact remaining
     promotion/customer-hardware gates.
6. `WARSOC_END_TO_END_PRODUCT_AND_OPERATOR_GUIDE.md`
   - Shorter product, onboarding, agent, detection, dashboard, retention, and
     operating guide.
7. `PRODUCTION_ACCEPTANCE_TEST.md`
   - Current production acceptance evidence and the remaining human or
     infrastructure proofs.
8. `OPS_ACCOUNT_PROVISIONING.md`
   - Creating a new customer tenant, handing over its first admin account, and
     inviting customer team users.
9. `PRODUCTION_BACKUP_RUNBOOK.md`
   - MongoDB backup and restore operations. Azure evidence archival is not a
     substitute for this backup process.
10. `FBR_POS_Integration_Contract.md`
   - Strict POS JSONL and authenticated FBR integration boundary.
11. `PILOT_UNSIGNED_AGENT_POLICY.md`
   - Controlled-pilot installer hash allowlisting while production code
     signing remains outstanding.

The local `WarSOC_End_to_End_Architecture_Map.pdf` is generated from the
current-state architecture document. PDF files are intentionally ignored by
Git, so the Markdown file remains the version-controlled authority.

Documents explicitly marked **HISTORICAL** are retained for engineering
history only. They must not be used for deployment, pricing, detection
coverage, retention, or customer claims.

When production behavior changes, update the current-state architecture,
operator guide, acceptance evidence, and this index in the same change.
