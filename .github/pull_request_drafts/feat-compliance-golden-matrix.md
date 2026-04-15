**Title**: feat(compliance): Golden Matrix & Alert Sieve

**Summary**

This draft PR contains the Golden Matrix changes and the SIEM alert-sieve (bouncer) implementation.

Do not merge — this is a Draft for review and verification only.

**Smoke Test Results (local)**

- 4688_signed_in_peca: True — `4688` was digitally signed and recorded in `peca_forensic_logs`.
- 4798_in_peca / 4798_in_fbr: False — `4798` was not vaulted into PECA or FBR (expected; Golden Matrix removal).
- 8233_in_logs: True — raw `8233` events were stored in `logs`.
- 8233_in_security_alerts: False — `8233` alerts were suppressed by the bouncer (raw retained, alert suppressed).

Commit / Branch:

- Branch: `feature/golden-matrix-hardening`
- Commit: HEAD locally (10ccc07) — "Golden Matrix: remove FBR/PECA tags from 4798; add 4688->peca; add SIEM bouncer for 8233"

Checklist

- [ ] CI / integration tests green
- [ ] Security review (keys / secrets check)
- [ ] Ops coordination for deployment (Redis/Mongo credentials)

Notes

- This PR was prepared after local smoke tests were executed. The smoke test harness is included at `scripts/run_smoke_tests.py` and writes results to `tmp/smoke_results.json`.
- DO NOT MERGE until CI and integration testing pass and the git-history purge & key rotation playbook are scheduled.
