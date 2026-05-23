import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics to track specific outcomes of the nuclear load
export let rateLimitHits = new Rate('rate_limit_hits');
export let acceptedPayloads = new Rate('accepted_payloads');

export let options = {
    // Disable TLS verification to allow testing against local self-signed Nginx certificates
    insecureSkipTLSVerify: true,
    
    // Simulate 500 Concurrent Virtual Users for 30 seconds
    stages: [
        { duration: '5s', target: 500 },  // Ramp-up to 500 VUs
        { duration: '20s', target: 500 }, // Sustain 500 VUs (The Nuclear Strike)
        { duration: '5s', target: 0 },    // Ramp-down
    ],
    
    thresholds: {
        // 95% of requests MUST have a response time < 200ms (verifying the O(1) Redis throttle speed)
        http_req_duration: ['p(95)<200'],
        
        // We EXPECT a high failure rate overall due to the strict 5000/min rate limit
        // 'http_req_failed' tracks any status >= 400
        http_req_failed: ['rate>0.5'], 
    },
};

export default function () {
    // We require a valid JWT token to pass the FastAPI dependency injection before hitting the rate limiter.
    // Run this script using: k6 run -e AGENT_TOKEN="<your_jwt_access_token>" k6_strike.js
    const token = __ENV.AGENT_TOKEN || "test_token_placeholder";
    
    // Targeting the Nginx gateway directly
    const url = 'https://host.docker.internal/api/v1/ingest/pulse';
    
    // Simulated Windows Event 4625 payload
    const payload = JSON.stringify([{
        "agent_id": "VM-STRIKE-01",
        "source_ip": "10.0.0.99",
        "user": "Administrator",
        "event_id": 4625,
        "event_uid": "k6-loadtest-" + __VU + "-" + __ITER,
        "message": "Event ID: 4625. Account Name: SYSTEM. Account Name: Administrator. Source Network Address: 10.0.0.99. Logon Type: 3.",
        "timestamp": new Date().toISOString(),
        "raw_data": {"raw": "Simulated brute force login via k6 load generator"},
        "processed_data": {
            "target_user": "Administrator",
            "source_network_address": "10.0.0.99",
            "logon_type": 3
        },
        "agent_signature": "dummy_signature_to_satisfy_pydantic_schema",
        "agent_version": "4.0-Omni"
    }]);

    const params = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
    };

    const res = http.post(url, payload, params);

    // Track outcomes explicitly
    const isRateLimited = res.status === 429;
    const isSuccess = res.status === 200;
    
    rateLimitHits.add(isRateLimited);
    acceptedPayloads.add(isSuccess);

    // Explicitly verify the transition from 200 OK -> 429 Too Many Requests
    check(res, {
        'status is 200 (Accepted by Gateway)': (r) => r.status === 200,
        'status is 429 (Rate Limit Enforced)': (r) => r.status === 429,
        // Since we are using a dummy signature, if the payload gets past the rate limiter, 
        // the backend ECDSA verification will reject it with a 401. This is expected behavior.
        'status is 401 (Bad Signature but survived Rate Limit)': (r) => r.status === 401,
    });

    // Micro-sleep to prevent the k6 engine from starving its own CPU threads
    sleep(0.01);
}
