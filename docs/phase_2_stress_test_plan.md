# Phase 2 Stress Test Plan

Scope: Ingestion throughput; vault integrity & TTL; RBAC/tenant isolation; noisy-event filtering.

1. Provision isolated test environment
2. Confirm TTL index exists
3. Verify consumer group & workers
4. Seed tenant entitlement cache
5. Run 1k concurrent ingestion
6. Measure queue lag and throughput
7. Verify cryptographic vault integrity
8. Perform TTL expiry smoke test
9. Run RBAC/tenancy access tests
10. Inject malformed/noise events
11. Collect logs, metrics, artifacts
12. Produce final test report
