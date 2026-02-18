// src/api.js

const API_BASE_URL = "http://127.0.0.1:8000/api/v1";

// ==========================================
// 🛠️ HELPER FUNCTIONS
// ==========================================

const getHeaders = (isMultipart = false) => {
  const token = localStorage.getItem("warsoc_token") || localStorage.getItem("token");
  const headers = {};
  
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // Browser sets Content-Type for file uploads automatically
  if (!isMultipart) {
    headers["Content-Type"] = "application/json";
  }
  
  return headers;
};

const request = async (endpoint, options = {}) => {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: { ...getHeaders(options.isMultipart), ...options.headers },
    });

    // Handle Session Expiry
    if (response.status === 401) {
      localStorage.clear();
      window.location.href = "/login";
      throw new Error("Session expired. Please login again.");
    }

    // Handle PDF Download (Blob)
    if (options.isBlob) {
        if (!response.ok) throw new Error("Download failed");
        return await response.blob();
    }

    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "API Request Failed");
    return data;

  } catch (err) {
    throw err;
  }
};

// ==========================================
// 📊 DASHBOARD & FILES API
// ==========================================
export const api = {
  // Get all analysis history
  getAnalyses: () => request("/upload/results"), 
  
  // Upload log file
  uploadLog: (file) => {
    const formData = new FormData();
    formData.append("file", file);
    return request("/upload/analyze", {
      method: "POST",
      body: formData,
      isMultipart: true,
    });
  },

  // Delete file
  deleteFile: (id) => request(`/upload/delete/${id}`, { method: "DELETE" }),

  // Download Report
  getReport: (id) => request(`/upload/report/${id}`, { isBlob: true }),
};

// ==========================================
// 🛡️ THREAT INTEL & MITIGATION API (UPDATED)
// ==========================================
export const threatIntel = {
  // ✅ BAN IP (New Endpoint)
  mitigateIP: (ip, reason) => request("/threat-intel/mitigate", {
    method: "POST",
    body: JSON.stringify({ ip, reason })
  }),

  // ✅ UNBAN/REVOKE IP (New Endpoint)
  revokeIP: (ip) => request("/threat-intel/revoke", {
    method: "POST",
    body: JSON.stringify({ ip })
  }),

  // Get List of Blocked IPs (Uses existing firewall list endpoint)
  getBlockedList: () => request("/firewall/list")
};

// ==========================================
// 🔐 AUTHENTICATION API
// ==========================================

// 1. LOGIN USER
export const loginUser = async (username, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, { 
        method: "POST", 
        headers: { "Content-Type": "application/json" }, 
        body: JSON.stringify({ 
            username: username, 
            password: password 
        })
    });

    if(!response.ok) { 
        const d = await response.json(); 
        
        let errorMsg = "Login failed";
        if (typeof d.detail === 'string') {
            errorMsg = d.detail;
        } else if (Array.isArray(d.detail)) {
            errorMsg = d.detail.map(e => e.msg).join(", ");
        } else if (typeof d.detail === 'object') {
            errorMsg = JSON.stringify(d.detail);
        }
        
        throw new Error(errorMsg); 
    }
    return await response.json();
};

// 2. REGISTER USER
export const registerUser = async (name, email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ full_name: name, username: name, email, password }),
    });
    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || "Signup failed");
    }
    return await response.json();
};

// 3. UPDATE PLAN
export const updateUserPlan = async (username, planName) => {
    const response = await fetch(`${API_BASE_URL}/auth/update-plan`, {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            "Authorization": `Bearer ${localStorage.getItem("token")}` 
        },
        body: JSON.stringify({ 
            username: username,
            plan_name: planName 
        })
    });

    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || "Plan update failed");
    }
    return await response.json();
};