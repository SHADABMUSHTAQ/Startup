import { toast } from 'react-toastify'; // [cite: 51]

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

const getHeaders = (isMultipart = false) => {
  // 🔒 SECURITY FIX: Token is now in HttpOnly cookie (browser sends automatically)
  // NO LONGER: const token = localStorage.getItem("token");
  const headers = {};
  // Authorization header no longer needed - cookie sent automatically
  if (!isMultipart) headers["Content-Type"] = "application/json";
  return headers;
};

const request = async (endpoint, options = {}) => {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    credentials: "include",  // 🔒 Browser automatically sends HttpOnly cookie
    headers: { ...getHeaders(options.isMultipart), ...options.headers },
  });

  // 🚨 Handle 403 gracefully: Stop the Death Loop
  if (response.status === 403) {
    const errData = await response.clone().json().catch(() => ({}));
    toast.error(errData.detail || "Premium Feature: Please upgrade your plan.", { theme: "dark" });
    return { data: [], status: "error", code: 403, detail: errData.detail };
  }

  if (response.status === 401) {
    if (window.location.pathname !== "/login") {
      // 🔒 SECURITY FIX: Cookie is automatically cleared by backend on logout
      window.location.href = "/login";
    }
    throw new Error("Session expired.");
  }

  if (response.status === 429) {
    throw new Error("Too many requests. Please wait a moment and try again.");
  }

  if (options.isBlob) {
      if (!response.ok) throw new Error("Download failed");
      return await response.blob();
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "API Request Failed");
  return data;
};

export const api = {
  // 📁 PIPE 1: Fetches Manual File Uploads (Sidebar)
  getAnalyses: () => request("/upload/results"), 
  
  // 🔥 PIPE 2: Fetches Live Windows Agent Logs (Main Table)
  getLiveLogs: () => request("/logs"), 

  uploadLog: (file) => {
    const formData = new FormData();
    formData.append("file", file);
    return request("/upload/analyze", {
      method: "POST",
      body: formData,
      isMultipart: true,
    });
  },
  deleteFile: (id) => request(`/upload/delete/${id}`, { method: "DELETE" }),
  getReport: (id) => request(`/upload/report/${id}`, { isBlob: true }),
};

export const threatIntel = {
  mitigateIP: (ip, reason) => request("/mitigate", {
    method: "POST",
    body: JSON.stringify({ ip, reason })
  }),
  revokeIP: (ip) => request("/revoke", {
    method: "POST",
    body: JSON.stringify({ ip })
  }),
  getBlockedList: () => request("/list"),
  freshStart: () => request("/session/fresh-start", { method: "POST" }),
  downloadAgent: () => request("/agent/download", { isBlob: true })
};

export const loginUser = async (username, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, { 
        method: "POST", 
        headers: { "Content-Type": "application/json" }, 
        body: JSON.stringify({ username, password })
    });
    
    if (response.status === 403) {
        toast.error("Access Denied: Your assigned role does not have authorization for this action."); // 
        throw new Error("Access Denied (403)");
    }
    if (response.status === 429) {
        throw new Error("Too many login attempts. Please wait a moment and try again.");
    }
    if(!response.ok) { 
        const d = await response.json().catch(() => ({})); 
        throw new Error(d.detail || "Login failed"); 
    }
    return await response.json();
};

export const registerUser = async (name, email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" }, 
        body: JSON.stringify({ full_name: name, username: name, email, password }),
    });
    if (response.status === 429) {
        throw new Error("Too many signup attempts. Please wait a moment and try again.");
    }
    if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || "Signup failed");
    }
    return await response.json();
};

export const updateUserPlan = async (username, planName) => {
    const response = await fetch(`${API_BASE_URL}/auth/update-plan`, {
        method: "POST",
        credentials: "include",  // 🔒 Browser sends HttpOnly cookie automatically
        headers: { 
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ username, plan_name: planName })
    });
    
    if (response.status === 403) {
        toast.error("Access Denied: Your assigned role does not have authorization for this action."); // 
        throw new Error("Access Denied (403)");
    }
    if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || "Plan update failed");
    }
    return await response.json();
};