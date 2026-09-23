import { toast } from "react-toastify";
import { useAuthStore } from './store/authStore';
import { formatApiErrorData } from './utils/apiError';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || (import.meta.env.PROD ? '/api/v1' : 'http://127.0.0.1:8000/api/v1');

const getHeaders = (isMultipart = false, method = 'GET') => {
  const headers = {};
  if (!isMultipart) headers["Content-Type"] = "application/json";

  const csrfToken = useAuthStore.getState().csrfToken;
  if (csrfToken && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase())) {
      headers['X-CSRF-Token'] = csrfToken;
  }
  return headers;
};

const request = async (endpoint, options = {}) => {
  const method = options.method || 'GET';
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    credentials: "include",
    headers: { ...getHeaders(options.isMultipart, method), ...options.headers },
  });

  // 🚨 Handle 403 gracefully: Stop the Death Loop
  if (response.status === 403) {
    const errData = await response.clone().json().catch(() => ({}));
    const detail = formatApiErrorData(errData, "You do not have access to this action.", response.status);
    toast.error(detail, { theme: "dark" });
    const error = new Error(detail);
    error.status = 403;
    throw error;
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
  if (!response.ok) throw new Error(formatApiErrorData(data, "Request failed. Please try again.", response.status));
  return data;
};

export const api = {
  // 📁 PIPE 1: Fetches Manual File Uploads (Sidebar)
  getAnalyses: () => request("/upload/results"), 
  
  // 🔥 PIPE 2: Fetches live hot-storage alerts with pagination
  getLiveLogs: (limit = 500) => {
    const cappedLimit = Math.min(Number(limit) || 500, 500);
    return request(`/alerts?limit=${cappedLimit}`);
  },

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
  downloadAgent: () =>
    window.location.assign(`${API_BASE_URL.replace(/\/$/, "")}/agent/download`)
};

export const loginUser = async (username, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, { 
        method: "POST", 
        credentials: "include",
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
        const message = response.status === 401
          ? "Invalid email or password."
          : formatApiErrorData(d, "Login failed. Please try again.", response.status);
        throw new Error(message);
    }
    return await response.json();
};
