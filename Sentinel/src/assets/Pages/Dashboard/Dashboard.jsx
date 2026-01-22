import React, { useState, useEffect } from "react";
import "./Dashboard.css";
import Alert from "../../Components/Alert/Alert";
import { useNavigate } from "react-router-dom"; // ✅ Navigation for Security Lock
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
} from "recharts";

function Dashboard() {
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [logs, setLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [alert, setAlert] = useState(null);
  
  // ✅ MODAL STATES
  const [viewFile, setViewFile] = useState(null);       // Report dekhne ke liye
  const [fileToDelete, setFileToDelete] = useState(null); // Delete confirm karne ke liye

  const navigate = useNavigate(); // Hook for redirection

  const allowedFormats = ["csv", "evtx", "log"];

  // ✅✅✅ 1. SECURITY LOCK (Payment Check) ✅✅✅
  useEffect(() => {
    const userData = JSON.parse(localStorage.getItem("user_data"));
    
    // Agar User Login nahi hai YA User ke paas Plan nahi hai
    if (!userData || !userData.hasPlan) {
      // User ko wapis Home/Pricing page par bhej do
      navigate("/"); 
    }
  }, [navigate]);

  // --- HELPER ---
  const mapSeverityToLevel = (severity) => {
    const s = severity?.toLowerCase() || "info";
    if (s === "critical" || s === "high") return "ERROR";
    if (s === "medium") return "WARN";
    return "INFO";
  };

  // 2. FETCH HISTORY
  useEffect(() => { fetchHistory(); }, []);

  const fetchHistory = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;
      const res = await fetch("http://127.0.0.1:8000/api/v1/files/results?limit=10", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        const formattedFiles = data.map(f => ({
            name: f.filename, type: f.filename.split('.').pop(), size: "Unknown",
            analysisId: f._id, status: f.status, findings: f.findings, uploaded_at: f.uploaded_at
        }));
        setFiles(formattedFiles);
        if (formattedFiles.length > 0) setSelectedFile(formattedFiles[0]);
      }
    } catch (err) { console.error("Network Error:", err); }
  };

  // 3. POLL BACKEND (Refresh Status)
  useEffect(() => {
    const interval = setInterval(async () => {
      const token = localStorage.getItem("token");
      if (!token) return;
      const updatedFiles = await Promise.all(
        files.map(async (f) => {
          if (f.status === "completed" && f.findings) return f;
          if (!f.analysisId) return f;
          try {
            const res = await fetch(`http://127.0.0.1:8000/api/v1/files/results/${f.analysisId}`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (!res.ok) return f;
            const data = await res.json();
            if (data.status === "completed") return { ...f, status: "completed", findings: data.findings || [] };
            return { ...f, status: data.status || "pending" };
          } catch { return f; }
        })
      );
      if (JSON.stringify(updatedFiles) !== JSON.stringify(files)) setFiles(updatedFiles);
    }, 5000);
    return () => clearInterval(interval);
  }, [files]);

  // 4. UPDATE LOGS VIEW
  useEffect(() => {
    if (selectedFile) {
        const currentFile = files.find(f => f.analysisId === selectedFile.analysisId);
        if (currentFile && currentFile.findings) {
            const formattedLogs = currentFile.findings.map((item, index) => ({
                id: index, time: item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : "N/A",
                level: mapSeverityToLevel(item.severity), message: item.summary || item.type || "Threat Detected"
            }));
            setLogs(formattedLogs);
        } else { setLogs([]); }
    } else { setLogs([]); }
  }, [files, selectedFile]);

  // ✅✅✅ 5. FILE UPLOAD (With Duplicate Check) ✅✅✅
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    const token = localStorage.getItem("token");
    if (!token) { 
        setAlert({ type: "error", message: "You must be logged in to upload!" }); 
        return; 
    }
    
    const ext = file.name.split(".").pop().toLowerCase();
    if (!allowedFormats.includes(ext)) { 
        setAlert({ type: "error", message: "❌ Only CSV, EVTX, or LOG files allowed!" }); 
        return; 
    }

    // 🛑 DUPLICATE CHECK
    const isDuplicate = files.some(f => f.name === file.name);
    if (isDuplicate) {
        setAlert({ type: "warning", message: "⚠️ File already exists! Please rename or delete the old one." });
        return; // Upload rok do
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/files/analyze", {
        method: "POST", headers: { "Authorization": `Bearer ${token}` }, body: formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Upload failed");
      
      const newFile = {
        name: file.name, type: ext, size: (file.size / 1024).toFixed(2) + " KB", rawSize: file.size,
        analysisId: data.analysis_id, status: "queued", findings: null
      };
      
      setFiles([newFile, ...files]);
      setSelectedFile(newFile);
      setLogs([]); 
      setAlert({ type: "success", message: `✅ ${file.name} uploaded!` });
    } catch (err) { setAlert({ type: "error", message: "Upload failed: " + err.message }); }
  };

  // ✅ 6. INITIATE DELETE (Opens Modal)
  const confirmDelete = (e, file) => {
    e.stopPropagation();
    setFileToDelete(file);
  };

  // ✅ 7. EXECUTE DELETE (Called from Modal)
  const executeDelete = async () => {
    if (!fileToDelete) return;
    const token = localStorage.getItem("token");

    try {
        const res = await fetch(`http://127.0.0.1:8000/api/v1/files/delete/${fileToDelete.analysisId}`, {
            method: "DELETE",
            headers: { "Authorization": `Bearer ${token}` }
        });

        if (res.ok) {
            const updatedFiles = files.filter(f => f.analysisId !== fileToDelete.analysisId);
            setFiles(updatedFiles);
            if (selectedFile && selectedFile.analysisId === fileToDelete.analysisId) {
                setSelectedFile(updatedFiles.length > 0 ? updatedFiles[0] : null);
            }
            setAlert({ type: "success", message: "File Deleted Successfully" });
        } else {
            setAlert({ type: "error", message: "Failed to delete file" });
        }
    } catch (err) {
        setAlert({ type: "error", message: "Network Error" });
    } finally {
        setFileToDelete(null); // Close Modal
    }
  };

  // 8. DOWNLOAD REPORT
  const handleDownloadReport = async (fileObj = null) => {
    const targetFile = fileObj || selectedFile;
    if (!targetFile || !targetFile.analysisId) return;
    const token = localStorage.getItem("token");
    if (!token) { setAlert({ type: "error", message: "Please login to download reports." }); return; }

    try {
        setAlert({ type: "info", message: "Generating Report..." });
        const res = await fetch(`http://127.0.0.1:8000/api/v1/files/report/${targetFile.analysisId}`, {
            headers: { "Authorization": `Bearer ${token}` }
        });
        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = `WARSOC_Report_${targetFile.name}.pdf`;
            document.body.appendChild(a); a.click(); a.remove();
            setAlert({ type: "success", message: "Report Downloaded Successfully!" });
        } else { setAlert({ type: "error", message: "Failed to generate report." }); }
    } catch (err) { console.error(err); setAlert({ type: "error", message: "Error downloading report." }); }
  };

  const filteredLogs = logs.filter(log => log.message.toLowerCase().includes(search.toLowerCase()));
  const chartData = [ { name: "Events", value: logs.length }, { name: "Errors", value: logs.filter((l) => l.level === "ERROR").length }, { name: "Warnings", value: logs.filter((l) => l.level === "WARN").length } ];
  const COLORS = ["#4da6ff", "#ff4d4d", "#ffc107"];

  return (
    <div className="dashboard">
      {alert && <Alert type={alert.type} message={alert.message} onClose={() => setAlert(null)} />}

      {/* ✅✅✅ VIEW REPORT MODAL ✅✅✅ */}
      {viewFile && (
        <div className="modal-overlay" onClick={() => setViewFile(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>🛡️ Analysis Report: {viewFile.name}</h2>
              <button className="close-btn" onClick={() => setViewFile(null)}>×</button>
            </div>
            <div className="modal-body">
              <div className="report-summary">
                <div className="summary-box"><h3>{viewFile.findings ? viewFile.findings.length : 0}</h3><span>Events</span></div>
                <div className="summary-box"><h3 style={{color: '#ff4d4d'}}>{viewFile.findings ? viewFile.findings.filter(f => f.severity === 'critical' || f.severity === 'high').length : 0}</h3><span>Critical</span></div>
                <div className="summary-box"><h3 style={{color: '#feca57'}}>{viewFile.findings ? viewFile.findings.filter(f => f.severity === 'medium').length : 0}</h3><span>Warnings</span></div>
              </div>
              <div className="findings-list">
                {viewFile.findings && viewFile.findings.length > 0 ? (
                  viewFile.findings.map((finding, idx) => (
                    <div key={idx} className={`finding-row ${finding.severity || 'info'}`}>
                      <div style={{display:'flex', justifyContent:'space-between'}}><strong>{finding.type || "Observation"}</strong><span className="finding-timestamp">{finding.timestamp}</span></div>
                      <p>{finding.details || finding.summary}</p>
                    </div>
                  ))
                ) : ( <p style={{textAlign:'center', padding:'20px', color: '#666'}}>No threats detected. ✅</p> )}
              </div>
            </div>
            <div className="modal-footer">
              <button onClick={() => handleDownloadReport(viewFile)} style={{padding:'10px 18px', background:'#4da6ff', color:'white', border:'none', borderRadius:'6px'}}>📥 Download PDF</button>
              <button onClick={() => setViewFile(null)} style={{padding:'10px 18px', background:'#e2e8f0', color:'#475569', border:'none', borderRadius:'6px'}}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* ✅✅✅ DELETE CONFIRMATION MODAL ✅✅✅ */}
      {fileToDelete && (
        <div className="modal-overlay" onClick={() => setFileToDelete(null)}>
          <div className="modal-content delete-confirmation" onClick={(e) => e.stopPropagation()}>
            <div className="delete-icon-circle">🗑️</div>
            <h2 style={{color: '#fff', marginBottom: '10px'}}>Delete File?</h2>
            <p style={{color: '#94a3b8', fontSize: '0.95rem'}}>
              Are you sure you want to delete <strong>{fileToDelete.name}</strong>?<br/>
              This action cannot be undone.
            </p>
            <div className="modal-actions">
              <button className="btn-cancel" onClick={() => setFileToDelete(null)}>Cancel</button>
              <button className="btn-delete" onClick={executeDelete}>Delete</button>
            </div>
          </div>
        </div>
      )}

      {/* --- DASHBOARD CONTENT --- */}
      <div className="stats">
        <div className="card"><h3>{logs.length}</h3><p>Total Events</p></div>
        <div className="card" style={{borderBottom: "4px solid #ff4d4d"}}><h3>{logs.filter((l) => l.level === "ERROR").length}</h3><p>Critical Errors</p></div>
        <div className="card" style={{borderBottom: "4px solid #ffc107"}}><h3>{logs.filter((l) => l.level === "WARN").length}</h3><p>Warnings</p></div>
        <div className="card"><h3>{files.length}</h3><p>Files History</p></div>
      </div>

      <div className="upload-box">
        <h2>Upload Security Data</h2>
        <input type="file" onChange={handleFileUpload} />
        <p className="upload-hint">Allowed: CSV, EVTX, LOG</p>
        <div className="file-list">
          {files.map((f, i) => (
            <div key={i} className={`file-item ${selectedFile?.analysisId === f.analysisId ? "active" : ""}`} onClick={() => setSelectedFile(f)} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ flex: 1 }}>📄 {f.name} - <em className={f.status === "completed" ? "text-green" : "text-yellow"}>{f.status || "pending"}</em></div>
              <div className="action-buttons" style={{display:'flex', gap:'8px'}}>
                <button onClick={(e) => { e.stopPropagation(); setViewFile(f); }} style={{background: "rgba(77, 166, 255, 0.15)", border: "none", cursor: "pointer", color: "#4da6ff", fontSize: "1.1rem", padding: "6px", borderRadius: "50%", width: "32px", height: "32px"}} title="View Report">👁️</button>
                <button onClick={(e) => confirmDelete(e, f)} style={{background: "rgba(255, 77, 77, 0.15)", border: "none", cursor: "pointer", color: "#ff4d4d", fontSize: "1.1rem", padding: "6px", borderRadius: "50%", width: "32px", height: "32px"}} title="Delete File">🗑️</button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {logs.length > 0 ? (
      <div className="charts">
        <ResponsiveContainer width="30%" height={250}><BarChart data={chartData}><XAxis dataKey="name" /><YAxis /><Tooltip /><Bar dataKey="value" fill="#4da6ff" /></BarChart></ResponsiveContainer>
        <ResponsiveContainer width="30%" height={250}><LineChart data={chartData}><XAxis dataKey="name" /><YAxis /><Tooltip /><Line type="monotone" dataKey="value" stroke="#ff4d4d" /></LineChart></ResponsiveContainer>
        <ResponsiveContainer width="30%" height={250}><PieChart><Pie data={chartData} dataKey="value" cx="50%" cy="50%" outerRadius={80} label>{chartData.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index]} />)}</Pie><Tooltip /></PieChart></ResponsiveContainer>
      </div>
      ) : ( <div style={{textAlign: 'center', margin: '20px', color: '#666'}}>{selectedFile ? "No threats detected..." : "Select a file to see analytics"}</div> )}

      {selectedFile && (
        <div className="logs">
          <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "15px"}}>
            <h2 style={{margin: 0}}>Logs from {selectedFile.name}</h2>
            <button onClick={() => handleDownloadReport(null)} style={{backgroundColor: "#4da6ff", color: "white", border: "none", padding: "8px 15px", borderRadius: "5px", cursor: "pointer", fontWeight: "bold", display: "flex", alignItems: "center", gap: "5px"}}>📄 Download Report</button>
          </div>
          <input type="text" placeholder="Search logs..." value={search} onChange={(e) => setSearch(e.target.value)} />
          <div className="log-box">
            {filteredLogs.length > 0 ? filteredLogs.map((log, i) => (
              <div key={i} className={`log-item ${log.level.toLowerCase()}`}><span>[{log.time}]</span><strong>{log.level}</strong> - {log.message}</div>
            )) : <p style={{padding: '10px'}}>No findings.</p>}
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;