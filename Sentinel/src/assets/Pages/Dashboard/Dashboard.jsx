import React, { useState } from "react";
import "./Dashboard.css";
import Alert from "../../Components/Alert/Alert";
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

function Dashboard() {
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [logs, setLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [alert, setAlert] = useState(null);

  // Allowed formats
  const allowedFormats = ["csv", "evtx", "log"];

  // File upload handler
const handleFileUpload = (e) => {
  const file = e.target.files[0];
  if (!file) return;

  const ext = file.name.split(".").pop().toLowerCase();

  // Check format
  if (!allowedFormats.includes(ext)) {
    setAlert({
      type: "error",
      message: "❌ Only CSV, EVTX, or LOG files allowed!",
    });
    return;
  }

  // ✅ Check duplicate file (by name + size in bytes)
  if (files.some((f) => f.name === file.name && f.rawSize === file.size)) {
    setAlert({
      type: "warning",
      message: `⚠️ ${file.name} is already uploaded!`,
    });
    return;
  }

  // Add new file
  const newFile = {
    name: file.name,
    type: ext,
    size: (file.size / 1024).toFixed(2) + " KB",
    rawSize: file.size, // 👈 add raw size for comparison
  };
  setFiles([...files, newFile]);
  setSelectedFile(newFile);

  setAlert({
    type: "success",
    message: `✅ ${file.name} uploaded successfully!`,
  });

  // Fake logs
  const fakeLogs = [
    { time: "10:00", level: "INFO", message: "System boot successful" },
    { time: "10:05", level: "WARN", message: "Unusual login attempt detected" },
    { time: "10:10", level: "ERROR", message: "Failed authentication from 192.168.1.10" },
  ];
  setLogs(fakeLogs);
};



  // Filter logs by search
  const filteredLogs = logs.filter(
    (log) =>
      log.message.toLowerCase().includes(search.toLowerCase()) ||
      log.level.toLowerCase().includes(search.toLowerCase())
  );

  // Chart sample data
  const chartData = [
    { name: "Events", value: logs.length },
    { name: "Errors", value: logs.filter((l) => l.level === "ERROR").length },
    { name: "Warnings", value: logs.filter((l) => l.level === "WARN").length },
  ];
  const COLORS = ["#4da6ff", "#ff4d4d", "#ffc107"];

  return (
    <div className="dashboard">
      {/* 🔔 Alert Box */}
      {alert && (
        <Alert
          type={alert.type}
          message={alert.message}
          onClose={() => setAlert(null)}
        />
      )}

      {/* 📊 Stats Section */}
      <div className="stats">
        <div className="card">
          <h3>{logs.length}</h3>
          <p>Total Events</p>
        </div>
        <div className="card">
          <h3>{logs.filter((l) => l.level === "ERROR").length}</h3>
          <p>Errors</p>
        </div>
        <div className="card">
          <h3>{logs.filter((l) => l.level === "WARN").length}</h3>
          <p>Warnings</p>
        </div>
        <div className="card">
          <h3>{files.length}</h3>
          <p>Files Uploaded</p>
        </div>
      </div>

      {/* 📂 File Upload */}
      <div className="upload-box">
        <h2>Upload Security Data</h2>
        <input type="file" onChange={handleFileUpload} />
        <p className="upload-hint">Allowed: CSV, EVTX, LOG</p>
        <div className="file-list">
          {files.map((f, i) => (
            <div
              key={i}
              className={`file-item ${selectedFile?.name === f.name ? "active" : ""}`}
              onClick={() => setSelectedFile(f)}
            >
              📄 {f.name} ({f.size})
            </div>
          ))}
        </div>
      </div>

      {/* 📈 Charts */}
      <div className="charts">
        <ResponsiveContainer width="30%" height={250}>
          <BarChart data={chartData}>
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Bar dataKey="value" fill="#4da6ff" />
          </BarChart>
        </ResponsiveContainer>

        <ResponsiveContainer width="30%" height={250}>
          <LineChart data={chartData}>
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Line type="monotone" dataKey="value" stroke="#ff4d4d" />
          </LineChart>
        </ResponsiveContainer>

        <ResponsiveContainer width="30%" height={250}>
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              cx="50%"
              cy="50%"
              outerRadius={80}
              label
            >
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* 📜 Logs Viewer */}
      {selectedFile && (
        <div className="logs">
          <h2>Logs from {selectedFile.name}</h2>
          <input
            type="text"
            placeholder="Search logs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <div className="log-box">
            {filteredLogs.map((log, i) => (
              <div key={i} className={`log-item ${log.level.toLowerCase()}`}>
                <span>[{log.time}]</span>
                <strong>{log.level}</strong> - {log.message}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
