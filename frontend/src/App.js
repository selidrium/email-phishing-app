import React, { useState } from 'react';
import axios from 'axios';
import AdminPanel from './AdminPanel';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || "http://localhost:8000";

function App() {
    const [token, setToken] = useState("");
    const [result, setResult] = useState(null);
    const [file, setFile] = useState(null);
    const [message, setMessage] = useState("");
    const [messageType, setMessageType] = useState("info");
    const [username, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const [emailId, setEmailId] = useState(null);
    const [isAdmin, setIsAdmin] = useState(false);
    
    const showMessage = (msg, type = "info") => {
        setMessage(msg);
        setMessageType(type);
        setTimeout(() => setMessage(""), 5000);
    };

    const register = async () => {
        setIsLoading(true);
        try {
            await axios.post(`${API_BASE_URL}/auth/register`, {
                username,
                email,
                password
            });
            showMessage("Registration successful! You can now login.", "success");
        } catch (err) {
            showMessage(err.response?.data?.detail || "Registration failed.", "danger");
        } finally {
            setIsLoading(false);
        }
    };

    const login = async () => {
        setIsLoading(true);
        try {
            const res = await axios.post(`${API_BASE_URL}/auth/login`, {
                username,
                password
            });
            setToken(res.data.access_token);
            setIsLoggedIn(true);
            showMessage("Logged in successfully!", "success");
            // Add a small delay to ensure token is set before checking admin status
            setTimeout(async () => {
                await checkAdminStatus(res.data.access_token);
            }, 100);
        } catch (err) {
            showMessage(err.response?.data?.detail || "Login failed.", "danger");
        } finally {
            setIsLoading(false);
        }
    };

    const checkAdminStatus = async (accessToken) => {
        try {
            console.log('Checking admin status with token:', accessToken ? 'present' : 'missing');
            const response = await axios.get(`${API_BASE_URL}/admin/stats`, {
                headers: { Authorization: `Bearer ${accessToken || token}` }
            });
            console.log('Admin check successful:', response.status);
            setIsAdmin(true);
        } catch (err) {
            console.log('Admin check failed:', err.response?.status, err.response?.data);
            setIsAdmin(false);
        }
    };

    const upload = async () => {
        if (!file) {
            showMessage("Please select a file first.", "warning");
            return;
        }
        
        setIsLoading(true);
        const formData = new FormData();
        formData.append("file", file);
        
        try {
            const res = await axios.post(`${API_BASE_URL}/upload`, formData, {
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });
            setResult(res.data);
            setEmailId(res.data.email_id);
            showMessage("File analyzed successfully!", "success");
        } catch (err) {
            showMessage(err.response?.data?.detail || "Upload failed.", "danger");
        } finally {
            setIsLoading(false);
        }
    };

    const downloadPDF = async (emailId) => {
        try {
            const response = await fetch(`${API_BASE_URL}/export/pdf/${emailId}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `phishing_report_${emailId}.pdf`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            } else {
                showMessage('Failed to download PDF', 'error');
            }
        } catch (error) {
            showMessage('Error downloading PDF', 'error');
        }
    };

    const downloadCSVReport = async (emailId) => {
        try {
            const response = await fetch(`${API_BASE_URL}/export/csv/${emailId}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `phishing_report_${emailId}.csv`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            } else {
                showMessage('Failed to download CSV', 'error');
            }
        } catch (error) {
            showMessage('Error downloading CSV', 'error');
        }
    };

    const handleFileChange = (e) => {
        const selectedFile = e.target.files[0];
        if (selectedFile && selectedFile.name.endsWith('.eml')) {
            setFile(selectedFile);
            showMessage(`File selected: ${selectedFile.name}`, "info");
        } else {
            showMessage("Please select a valid .eml file.", "warning");
            setFile(null);
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.currentTarget.classList.add('dragover');
    };

    const handleDragLeave = (e) => {
        e.preventDefault();
        e.currentTarget.classList.remove('dragover');
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.currentTarget.classList.remove('dragover');
        const droppedFile = e.dataTransfer.files[0];
        if (droppedFile && droppedFile.name.endsWith('.eml')) {
            setFile(droppedFile);
            showMessage(`File dropped: ${droppedFile.name}`, "info");
        } else {
            showMessage("Please drop a valid .eml file.", "warning");
        }
    };

    return (
        <div className="min-vh-100 gradient-bg">
            <div className="container py-4">
                {/* Header */}
                <div className="text-center mb-5">
                    <div className="d-flex justify-content-between align-items-center mb-3">
                        {isLoggedIn && (
                            <div className="text-start">
                                <span className="text-white-50">Welcome, {username}</span>
                                {isAdmin && <span className="badge bg-warning ms-2">Admin</span>}
                            </div>
                        )}
                        {isLoggedIn && (
                            <button 
                                className="btn btn-outline-light btn-sm"
                                onClick={() => {
                                    setToken("");
                                    setIsLoggedIn(false);
                                    setIsAdmin(false);
                                    setResult(null);
                                    setFile(null);
                                    showMessage("Logged out successfully!", "info");
                                }}
                            >
                                <i className="bi bi-box-arrow-right me-2"></i>
                                Logout
                            </button>
                        )}
                    </div>
                    <h1 className="text-white display-4 fw-bold">
                        <i className="bi bi-shield-check me-3"></i>
                        Phishing Detection App
                    </h1>
                    <p className="text-white-50 lead">Secure email analysis with advanced threat detection</p>
                </div>

                {/* Message Alert */}
                {message && (
                    <div className={`alert alert-${messageType} alert-dismissible fade show`} role="alert">
                        {message}
                        <button type="button" className="btn-close" onClick={() => setMessage("")}></button>
                    </div>
                )}

                {/* Authentication Section */}
                {!isLoggedIn ? (
                    <div className="row justify-content-center">
                        <div className="col-md-6 col-lg-4">
                            <div className="card shadow-lg card-hover">
                                <div className="card-header bg-primary text-white text-center">
                                    <h4 className="mb-0">
                                        <i className="bi bi-person-circle me-2"></i>
                                        Authentication
                                    </h4>
                                </div>
                                <div className="card-body">
                                    <div className="mb-3">
                                        <label className="form-label">Username</label>
                                        <input 
                                            type="text" 
                                            className="form-control" 
                                            value={username} 
                                            onChange={e => setUsername(e.target.value)}
                                            placeholder="Enter username"
                                        />
                                    </div>
                                    <div className="mb-3">
                                        <label className="form-label">Email</label>
                                        <input 
                                            type="email" 
                                            className="form-control" 
                                            value={email} 
                                            onChange={e => setEmail(e.target.value)}
                                            placeholder="Enter email"
                                        />
                                    </div>
                                    <div className="mb-3">
                                        <label className="form-label">Password</label>
                                        <input 
                                            type="password" 
                                            className="form-control" 
                                            value={password} 
                                            onChange={e => setPassword(e.target.value)}
                                            placeholder="Enter password"
                                        />
                                    </div>
                                    <div className="d-grid gap-2">
                                        <button 
                                            className="btn btn-primary" 
                                            onClick={register}
                                            disabled={isLoading}
                                        >
                                            {isLoading ? (
                                                <>
                                                    <span className="spinner-border spinner-border-sm me-2"></span>
                                                    Registering...
                                                </>
                                            ) : (
                                                <>
                                                    <i className="bi bi-person-plus me-2"></i>
                                                    Register
                                                </>
                                            )}
                                        </button>
                                        <button 
                                            className="btn btn-success" 
                                            onClick={login}
                                            disabled={isLoading}
                                        >
                                            {isLoading ? (
                                                <>
                                                    <span className="spinner-border spinner-border-sm me-2"></span>
                                                    Logging in...
                                                </>
                                            ) : (
                                                <>
                                                    <i className="bi bi-box-arrow-in-right me-2"></i>
                                                    Login
                                                </>
                                            )}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                ) : (
                    isAdmin ? (
                        <AdminPanel token={token} />
                    ) : (
                        <div className="row justify-content-center">
                            <div className="col-lg-6 mb-4">
                                {/* Upload Section */}
                                <div className="card shadow-lg">
                                    <div className="card-header bg-primary text-white">
                                        <h4 className="mb-0">
                                            <i className="bi bi-upload me-2"></i>
                                            Upload Email File
                                        </h4>
                                    </div>
                                    <div className="card-body">
                                        <div 
                                            className="upload-area"
                                            onDragOver={handleDragOver}
                                            onDragLeave={handleDragLeave}
                                            onDrop={handleDrop}
                                        >
                                            <i className="bi bi-cloud-upload display-4 text-muted mb-3"></i>
                                            <h5>Drag & Drop your .eml file here</h5>
                                            <p className="text-muted">or</p>
                                            <input 
                                                type="file" 
                                                className="form-control" 
                                                accept=".eml"
                                                onChange={handleFileChange}
                                            />
                                            <small className="text-muted">Only .eml files are supported</small>
                                        </div>
                                        
                                        {file && (
                                            <div className="mt-3">
                                                <div className="alert alert-info">
                                                    <i className="bi bi-file-earmark me-2"></i>
                                                    Selected: {file.name}
                                                </div>
                                                <button 
                                                    className="btn btn-primary btn-lg w-100"
                                                    onClick={upload}
                                                    disabled={isLoading}
                                                >
                                                    {isLoading ? (
                                                        <>
                                                            <span className="spinner-border spinner-border-sm me-2"></span>
                                                            Analyzing...
                                                        </>
                                                    ) : (
                                                        <>
                                                            <i className="bi bi-search me-2"></i>
                                                            Analyze for Phishing
                                                        </>
                                                    )}
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                            <div className="w-100"></div>
                            <div className="col-12 mb-4 report-section-wide">
                                {/* Results Section */}
                                {result && result.report && (
                                    <div className="card shadow-lg">
                                        <div className="card-header bg-primary text-white">
                                            <h4 className="mb-0">
                                                <i className="bi bi-clipboard-data me-2"></i>
                                                🧾 Phishing Analysis & Email Forensics Report
                                            </h4>
                                        </div>
                                        <div className="card-body">
                                            {/* Report Metadata */}
                                            <h5 className="mb-3"><i className="bi bi-paperclip me-2"></i>Report Metadata</h5>
                                            <table className="table table-bordered table-sm mb-4">
                                                <thead className="table-dark">
                                                    <tr><th>Field</th><th>Value</th></tr>
                                                </thead>
                                                <tbody>
                                                    <tr><td>Report ID</td><td>{result.report.metadata?.message_id || 'UUID / Timestamp'}</td></tr>
                                                    <tr><td>Filename</td><td>{file?.name || 'original_email.eml'}</td></tr>
                                                    <tr><td>Upload Date</td><td>{new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC'}</td></tr>
                                                    <tr><td>Analyzed By</td><td>User: {username || 'alan.g@example.com'}</td></tr>
                                                    <tr><td>Phishing Score</td><td>{result.report.risk_scoring?.overall_risk_score || 0} / 100</td></tr>
                                                    <tr><td>Flagged as</td><td>{result.report.risk_scoring?.is_phishing ? 'Phishing' : 'Benign'}</td></tr>
                                                </tbody>
                                            </table>

                                            {/* Email Header Summary */}
                                            <h5 className="mb-3"><i className="bi bi-envelope me-2"></i>Email Header Summary</h5>
                                            <table className="table table-bordered table-sm mb-4">
                                                <thead className="table-dark">
                                                    <tr><th>Field</th><th>Value</th></tr>
                                                </thead>
                                                <tbody>
                                                    <tr><td>From</td><td>{result.report.metadata?.from || 'Unknown'}</td></tr>
                                                    <tr><td>To</td><td>{result.report.metadata?.to || 'Unknown'}</td></tr>
                                                    <tr><td>Subject</td><td>{result.report.metadata?.subject || 'Unknown'}</td></tr>
                                                    <tr><td>Date</td><td>{result.report.metadata?.date || 'Unknown'}</td></tr>
                                                    <tr><td>Message ID</td><td><code className="small">{result.report.metadata?.message_id || 'N/A'}</code></td></tr>
                                                </tbody>
                                            </table>

                                            {/* Email Delivery Chain */}
                                            <h5 className="mb-3"><i className="bi bi-diagram-3 me-2"></i>Email Delivery Chain (Received Headers)</h5>
                                            <table className="table table-bordered table-sm mb-4">
                                                <thead className="table-dark">
                                                    <tr><th>Hop</th><th>IP Address</th><th>Hostname</th><th>Timestamp</th></tr>
                                                </thead>
                                                <tbody>
                                                    {result.report.delivery_chain?.routing_path && result.report.delivery_chain.routing_path.length > 0 ? (
                                                        result.report.delivery_chain.routing_path.map((hop, idx) => (
                                                            <tr key={idx}>
                                                                <td>{hop.hop_number || idx + 1}</td>
                                                                <td>{hop.ip_addresses && hop.ip_addresses.length > 0 ? hop.ip_addresses.join(', ') : 'N/A'}</td>
                                                                <td>{hop.from_host || 'N/A'}</td>
                                                                <td>{hop.timestamp || 'N/A'}</td>
                                                            </tr>
                                                        ))
                                                    ) : (
                                                        <tr>
                                                            <td colSpan="4" className="text-center text-muted">No delivery chain data available</td>
                                                        </tr>
                                                    )}
                                                </tbody>
                                            </table>

                                            {/* Threat Indicators */}
                                            <h5 className="mb-3"><i className="bi bi-exclamation-triangle me-2"></i>Threat Indicators</h5>
                                            <table className="table table-bordered table-sm mb-4">
                                                <thead className="table-dark">
                                                    <tr><th>Indicator Type</th><th>Indicator</th><th>Description</th></tr>
                                                </thead>
                                                <tbody>
                                                    {result.report.threat_indicators && result.report.threat_indicators.length > 0 ? (
                                                        result.report.threat_indicators.map((indicator, idx) => (
                                                            <tr key={idx}>
                                                                <td>{indicator.type || 'Other'}</td>
                                                                <td>{indicator.value || indicator.description}</td>
                                                                <td>{indicator.description}</td>
                                                            </tr>
                                                        ))
                                                    ) : (
                                                        <tr>
                                                            <td colSpan="3" className="text-center text-muted">No threat indicators found</td>
                                                        </tr>
                                                    )}
                                                </tbody>
                                            </table>

                                            {/* VirusTotal IP Report Summary */}
                                            <h5 className="mb-3"><i className="bi bi-globe me-2"></i>VirusTotal IP Report Summary</h5>
                                            <table className="table table-bordered table-sm mb-4">
                                                <thead className="table-dark">
                                                    <tr><th>Field</th><th>Value</th></tr>
                                                </thead>
                                                <tbody>
                                                    <tr><td>IP Address</td><td>{result.report.metadata?.sender_ip || 'N/A'}</td></tr>
                                                    <tr><td>Harmless</td><td>{result.report.virustotal_summary?.ip_reputation?.harmless_count || 0}</td></tr>
                                                    <tr><td>Malicious</td><td>{result.report.virustotal_summary?.ip_reputation?.malicious_count || 0}</td></tr>
                                                    <tr><td>Suspicious</td><td>{result.report.virustotal_summary?.ip_reputation?.suspicious_count || 0}</td></tr>
                                                    <tr><td>Verdict</td><td>
                                                        {result.report.virustotal_summary?.ip_reputation?.verdict ? (
                                                            <span className={`badge ${result.report.virustotal_summary.ip_reputation.verdict === 'malicious' ? 'bg-danger' : result.report.virustotal_summary.ip_reputation.verdict === 'suspicious' ? 'bg-warning' : 'bg-success'}`}>
                                                                {result.report.virustotal_summary.ip_reputation.verdict}
                                                            </span>
                                                        ) : 'Unknown'}
                                                    </td></tr>
                                                </tbody>
                                            </table>

                                            {/* Attachments Summary */}
                                            <h5 className="mb-3"><i className="bi bi-paperclip me-2"></i>Attachments Summary</h5>
                                            <table className="table table-bordered table-sm mb-4">
                                                <thead className="table-dark">
                                                    <tr><th>File Name</th><th>Type</th><th>Size</th><th>Hash (SHA256)</th><th>VirusTotal</th><th>Suspicious</th></tr>
                                                </thead>
                                                <tbody>
                                                    {result.report.attachments && result.report.attachments.length > 0 ? (
                                                        result.report.attachments.map((att, idx) => (
                                                            <tr key={idx}>
                                                                <td>{att.filename || 'Unknown'}</td>
                                                                <td>{att.content_type || 'Unknown'}</td>
                                                                <td>{att.size ? (att.size / 1024).toFixed(0) + 'KB' : 'N/A'}</td>
                                                                <td><code className="small">{att.hash_sha256 ? att.hash_sha256.substring(0, 16) + '...' : 'N/A'}</code></td>
                                                                <td>
                                                                    {att.virustotal?.available ? (
                                                                        <span className={`badge ${att.virustotal.verdict === 'malicious' ? 'bg-danger' : att.virustotal.verdict === 'suspicious' ? 'bg-warning' : 'bg-success'}`}>
                                                                            {att.virustotal.verdict} ({att.virustotal.score})
                                                                        </span>
                                                                    ) : (
                                                                        <span className="badge bg-secondary">N/A</span>
                                                                    )}
                                                                </td>
                                                                <td>{att.suspicious ? <span className="text-success">✅ Yes</span> : <span className="text-danger">❌ No</span>}</td>
                                                            </tr>
                                                        ))
                                                    ) : (
                                                        // Fallback: show attachments from phishing analysis if available
                                                        result.report.detailed_analysis?.phishing_analysis?.attachment_analysis?.attachment_details && result.report.detailed_analysis.phishing_analysis.attachment_analysis.attachment_details.length > 0 ? (
                                                            result.report.detailed_analysis.phishing_analysis.attachment_analysis.attachment_details.map((att, idx) => (
                                                                <tr key={idx}>
                                                                    <td>{att.filename || 'Unknown'}</td>
                                                                    <td>{att.content_type || 'Unknown'}</td>
                                                                    <td>{att.size ? (att.size / 1024).toFixed(0) + 'KB' : 'N/A'}</td>
                                                                    <td><code className="small">{att.hash_sha256 ? att.hash_sha256.substring(0, 16) + '...' : 'N/A'}</code></td>
                                                                    <td><span className="badge bg-secondary">N/A</span></td>
                                                                    <td>{att.suspicious ? <span className="text-success">✅ Yes</span> : <span className="text-danger">❌ No</span>}</td>
                                                                </tr>
                                                            ))
                                                        ) : (
                                                            <tr>
                                                                <td colSpan="6" className="text-center text-muted">No attachments found</td>
                                                            </tr>
                                                        )
                                                    )}
                                                </tbody>
                                            </table>

                                            {/* Export Buttons */}
                                            <div className="d-flex justify-content-center gap-3 mt-4">
                                                <button 
                                                    className="btn btn-success"
                                                    onClick={() => downloadPDF(emailId)}
                                                    title="Download PDF Report"
                                                    disabled={!emailId}
                                                >
                                                    <i className="bi bi-file-pdf me-2"></i>
                                                    Export PDF
                                                </button>
                                                <button 
                                                    className="btn btn-info"
                                                    onClick={() => downloadCSVReport(emailId)}
                                                    title="Download CSV Report"
                                                    disabled={!emailId}
                                                >
                                                    <i className="bi bi-file-earmark-spreadsheet me-2"></i>
                                                    Export CSV
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    )
                )}
            </div>
        </div>
    );
}

export default App;
