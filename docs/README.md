# WarSOC Documentation Index

**Current as of:** 2026-08-26

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
12. `WARSOC_FBR_RETENTION_PRODUCT_DECISION_2026-08-24.md`
    and `WARSOC_PECA_RETENTION_PRODUCT_DECISION_2026-08-24.md`
   - Active decisions that make new FBR and PECA evidence inherit the existing
     tenant retention entitlement while preserving historical locked evidence.
13. `WARSOC_RELEASE_VALIDATION_2026-08-26.md`
   - Exact candidate validation performed after the PECA retention correction,
     including passed source gates and the remaining real Redis/Azure/frontend
     and physical-lab gates.
14. `OCI_BACKEND_BOOTSTRAP_RUNBOOK.md`
   - ARM64 Ubuntu host preparation, OCI/UFW/Docker network boundaries, SSH
     commands, and the stop point before a production backend migration.
15. `OCI_EMERGENCY_BACKEND_MIGRATION_RUNBOOK.md`
   - Exact clean-start restoration of the last production-proven backend to
     OCI, including immutable transfer, ARM64 build, DNS/TLS activation, and
     post-cutover checks.

The local `WarSOC_End_to_End_Architecture_Map.pdf` is generated from the
current-state architecture document. PDF files are intentionally ignored by
Git, so the Markdown file remains the version-controlled authority.

Documents explicitly marked **HISTORICAL** are retained for engineering
history only. They must not be used for deployment, pricing, detection
coverage, retention, or customer claims.

When production behavior changes, update the current-state architecture,
operator guide, acceptance evidence, and this index in the same change.
