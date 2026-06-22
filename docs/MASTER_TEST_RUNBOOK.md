### **WarSOC Master E2E Test Runbook (v1.0)**

#### **Phase 1: Ingestion & Cryptography (The Front Door)**

*Our goal is to ensure the API acts as a pure, unbreakable pipe, and the workers correctly authenticate the data.*

* **Test 1.1: Standard Log Injection (Happy Path)**
* **Action:** Send a valid, ECDSA-signed log via Postman/cURL to the `/inject` route.
* **Expected Result:** API returns `202 Accepted` in under 50ms. Log appears in Redis stream.


* **Test 1.2: Invalid Signature Rejection (The Bouncer)**
* **Action:** Send a log with a tampered ECDSA signature or an invalid public key.
* **Expected Result:** API returns `202 Accepted` (Dumb Pipe), but the SIEM Worker immediately logs a signature failure, `xack`s the message, and drops it. It must **not** reach MongoDB.


* **Test 1.3: Malformed JSON Handling**
* **Action:** Send a broken JSON payload (missing brackets, wrong types).
* **Expected Result:** API rejects it immediately with a `422 Unprocessable Entity` or `400 Bad Request`.



#### **Phase 2: Compliance Logic & Rules Engine (The Brain)**

*This is where you catch your PECA failures. We must verify the engine tags logs correctly.*

* **Test 2.1: PECA Unauthorized Access Trigger**
* **Action:** Inject a synthetic Windows Event Log representing multiple failed RDP logins (Event ID 4625).
* **Expected Result:** The SIEM worker processes the log, identifies the pattern, and tags it in MongoDB with `compliance: PECA`.


* **Test 2.2: FBR Data Integrity Trigger**
* **Action:** Inject a log simulating a critical file modification on a monitored directory.
* **Expected Result:** The log is successfully written to MongoDB and tagged with `compliance: FBR`.


* **Test 2.3: The "Noise" Filter**
* **Action:** Inject standard, non-critical background noise logs (e.g., routine network pings).
* **Expected Result:** Logs are stored for auditing but do NOT trigger compliance alerts or bloat the dashboard UI.



#### **Phase 3: Saturation & Hardware Resilience (The Stress Test)**

*The system must not buckle under a corporate network load.*

* **Test 3.1: The 1,000-User Enterprise Sweep**
* **Action:** Run Locust with 1,000 users, 100 spawn rate, for 3 minutes against the new 4 vCPU droplet.
* **Expected Result:** API maintains a P99 response time under 100ms. Zero `502 Bad Gateway` errors from Nginx. CPU usage on the `api` container stays below 85%.


* **Test 3.2: Database Backpressure Recovery**
* **Action:** Temporarily shut down the MongoDB container while the API is receiving logs, wait 10 seconds, and turn it back on.
* **Expected Result:** Redis queues the incoming logs safely. When MongoDB returns, the SIEM workers drain the Redis queue and write everything without losing a single event.



#### **Phase 4: Client Interface & Reporting (The Delivery)**

*If the UI fails, the client thinks the whole system is broken.*

* **Test 4.1: Live Dashboard Websockets/Polling**
* **Action:** Open the frontend dashboard. Inject a critical PECA violation log via the backend.
* **Expected Result:** The dashboard updates to show the new alert within 3 seconds without requiring a manual page refresh.


* **Test 4.2: CSV Compliance Export**
* **Action:** Click the "Export Logs" button for a specific date range.
* **Expected Result:** The system generates and downloads a clean, correctly formatted CSV containing all cryptographic signatures and compliance tags required for legal audits.



---

### The Execution Protocol

From this moment on, whenever you write a new feature, you write the test for it in this book *first*. Whenever you change the code, you run down this checklist. If a test fails, you don't merge the code to `main`.
