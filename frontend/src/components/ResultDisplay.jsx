import React from 'react';
import { Card, Button, Table, Badge, Alert, Modal } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import logger from '../services/logger';
import { useAuth } from '../services/authService';

function ResultDisplay({ analysisResult, onNewUpload }) {
  // Debug: log the analysisResult prop
  console.log("ResultDisplay analysisResult:", analysisResult);
  const navigate = useNavigate();
  const { user } = useAuth();

  // Add state for debug visibility
  const [showDebug, setShowDebug] = React.useState(false);
  const [showLogs, setShowLogs] = React.useState(false);
  const [downloading, setDownloading] = React.useState(false);
  const [downloadError, setDownloadError] = React.useState('');

  // Log when component mounts with analysis results
  React.useEffect(() => {
    if (analysisResult) {
      logger.info('Analysis results displayed', {
        riskScore: analysisResult.risk_assessment?.score,
        riskLevel: analysisResult.risk_assessment?.level,
        hasAttachments: analysisResult.attachments?.attachments?.length > 0,
        userId: user?.id
      });
    }
  }, [analysisResult, user]);

  const handleNewUpload = () => {
    logger.info('Starting new upload from results page');
    if (onNewUpload) {
      onNewUpload();
    } else {
      navigate('/upload');
    }
  };

  const getRiskLevelColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'high':
        return 'danger';
      case 'medium':
        return 'warning';
      case 'low':
        return 'success';
      default:
        return 'secondary';
    }
  };

  const renderThreatIntelligence = (threatData) => {
    if (!threatData?.threat_data || Object.keys(threatData.threat_data).length === 0) {
      return (
        <Card className="mb-4">
          <Card.Body>
            <h5>Threat Intelligence</h5>
            <Alert variant="info">No threat intelligence data available.</Alert>
          </Card.Body>
        </Card>
      );
    }

    return (
      <Card className="mb-4">
        <Card.Body>
          <h5>Threat Intelligence</h5>
          <Table striped bordered hover>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Abuse Score</th>
                <th>Country</th>
                <th>ISP</th>
                <th>Hostnames</th>
                <th>Last Reported</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(threatData.threat_data).map(([ip, data]) => (
                <tr key={ip}>
                  <td>{ip}</td>
                  <td>
                    <Badge bg={data.data?.abuseConfidenceScore > 50 ? 'danger' : 'success'}>
                      {data.data?.abuseConfidenceScore || 'N/A'}
                    </Badge>
                  </td>
                  <td>{data.data?.countryCode || 'N/A'}</td>
                  <td>{data.data?.isp || 'N/A'}</td>
                  <td>
                    {data.data?.hostnames?.map((hostname, i) => (
                      <div key={i}>{hostname}</div>
                    )) || 'N/A'}
                  </td>
                  <td>{data.data?.lastReportedAt ? new Date(data.data.lastReportedAt).toLocaleString() : 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card.Body>
      </Card>
    );
  };

  const renderServerHops = (headers) => {
    if (!headers?.server_hops || headers.server_hops.length === 0) {
      return (
        <Card className="mb-4">
          <Card.Body>
            <h5>Server Hops</h5>
            <Alert variant="info">No server hop information available.</Alert>
          </Card.Body>
        </Card>
      );
    }

    return (
      <Card className="mb-4">
        <Card.Body>
          <h5>Server Hops</h5>
          <Table striped bordered hover>
            <thead>
              <tr>
                <th>Server</th>
                <th>IP Address</th>
                <th>Header</th>
              </tr>
            </thead>
            <tbody>
              {headers.server_hops.map((hop, index) => (
                <tr key={index}>
                  <td>{hop.header && hop.header.match(/from ([^ ]+)/i) ? hop.header.match(/from ([^ ]+)/i)[1] : 'N/A'}</td>
                  <td>{hop.ip_addresses && hop.ip_addresses.length > 0 ? hop.ip_addresses.join(', ') : 'N/A'}</td>
                  <td>
                    <small className="text-muted">{hop.header || 'N/A'}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card.Body>
      </Card>
    );
  };

  const renderAttachments = (attachments) => {
    if (!attachments?.attachments || attachments.attachments.length === 0) {
      return (
        <Card className="mb-4">
          <Card.Body>
            <h5>Attachments</h5>
            <Alert variant="info">No attachments found in the email.</Alert>
          </Card.Body>
        </Card>
      );
    }

    return (
      <Card className="mb-4">
        <Card.Body>
          <h5>Attachments</h5>
          <Table striped bordered hover>
            <thead>
              <tr>
                <th>Filename</th>
                <th>Type</th>
                <th>Size</th>
                <th>Hash</th>
                <th>VirusTotal Status</th>
                <th>Detection Count</th>
              </tr>
            </thead>
            <tbody>
              {attachments.attachments.map((attachment, index) => (
                <tr key={index}>
                  <td>{attachment.filename || 'N/A'}</td>
                  <td>{attachment.type || 'N/A'}</td>
                  <td>{attachment.size ? `${(attachment.size / 1024).toFixed(2)} KB` : 'N/A'}</td>
                  <td>
                    <code>{attachment.hash ? `${attachment.hash.substring(0, 16)}...` : 'N/A'}</code>
                  </td>
                  <td>
                    {attachment.virustotal ? (
                      <a href={attachment.virustotal.permalink} target="_blank" rel="noopener noreferrer">
                        <Badge bg={attachment.virustotal.response_code === 1 ? 'success' : 'warning'}>
                          {attachment.virustotal.verbose_msg}
                        </Badge>
                      </a>
                    ) : (
                      'Not scanned'
                    )}
                  </td>
                  <td>
                    {attachment.virustotal ? (
                      `${attachment.virustotal.positives || 0}/${attachment.virustotal.total || 0}`
                    ) : (
                      'N/A'
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card.Body>
      </Card>
    );
  };

  const renderSuspiciousElements = (htmlContent) => {
    if (!htmlContent?.suspicious_elements || htmlContent.suspicious_elements.length === 0) {
      return (
        <Card className="mb-4">
          <Card.Body>
            <h5>Suspicious HTML Elements</h5>
            <Alert variant="success">No suspicious HTML elements found.</Alert>
          </Card.Body>
        </Card>
      );
    }

    return (
      <Card className="mb-4">
        <Card.Body>
          <h5>Suspicious HTML Elements</h5>
          <Table striped bordered hover>
            <thead>
              <tr>
                <th>Type</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {htmlContent.suspicious_elements.map((element, index) => (
                <tr key={index}>
                  <td>{element.type || 'N/A'}</td>
                  <td>
                    {element.type === 'hidden_link' ? (
                      <a href={element.href} target="_blank" rel="noopener noreferrer">
                        {element.text || element.href || 'N/A'}
                      </a>
                    ) : (
                      <code>{element.content || 'N/A'}</code>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card.Body>
      </Card>
    );
  };

  const renderSuspiciousPatterns = (language) => {
    if (!language?.suspicious_patterns || language.suspicious_patterns.length === 0) {
      return (
        <Card className="mb-4">
          <Card.Body>
            <h5>Suspicious Language Patterns</h5>
            <Alert variant="success">No suspicious language patterns found.</Alert>
          </Card.Body>
        </Card>
      );
    }

    return (
      <Card className="mb-4">
        <Card.Body>
          <h5>Suspicious Language Patterns</h5>
          <Table striped bordered hover>
            <thead>
              <tr>
                <th>Pattern</th>
              </tr>
            </thead>
            <tbody>
              {language.suspicious_patterns.map((pattern, index) => (
                <tr key={index}>
                  <td>{pattern.pattern}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card.Body>
      </Card>
    );
  };

  // Helper to get a safe filename for reports
  const getReportBaseName = () => {
    // Try to use the original filename if available, else fallback
    if (analysisResult.attachments?.attachments?.[0]?.filename) {
      return analysisResult.attachments.attachments[0].filename.replace(/\.[^/.]+$/, '');
    }
    if (analysisResult.subject) {
      return analysisResult.subject.replace(/[^a-zA-Z0-9_-]+/g, '_').slice(0, 32) || 'email_report';
    }
    return 'email_report';
  };

  // Helper to get the backend's report filename (if available)
  const getBackendReportName = (type) => {
    // If the backend returns a report filename, use it; else fallback
    if (analysisResult.report_filename) return analysisResult.report_filename;
    // Otherwise, try to use a hash or subject
    return `${getReportBaseName()}.${type}`;
  };

  // Download handler
  const handleDownload = async (type) => {
    setDownloading(true);
    setDownloadError('');
    const startTime = Date.now();

    try {
      logger.info('Starting report download', { type });
      const token = localStorage.getItem('token');
      const filename = getBackendReportName(type);
      const url = `/uploads/download/${type}/${filename}`;
      
      const response = await axios.post(
        url,
        analysisResult,
        {
          responseType: 'blob',
          headers: { Authorization: `Bearer ${token}` },
          baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
        }
      );

      const endTime = Date.now();
      logger.logApiRequest('POST', url, 200, endTime - startTime);

      // Create a blob and trigger download
      const blob = new Blob([response.data], { type: type === 'pdf' ? 'application/pdf' : 'text/csv' });
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = getReportBaseName() + (type === 'pdf' ? '.pdf' : '.csv');
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      logger.info('Report download completed', { 
        type,
        filename: link.download,
        size: blob.size
      });
    } catch (err) {
      setDownloadError('Failed to download report.');
      logger.logError(err, {
        type,
        filename: getBackendReportName(type)
      });
    }
    setDownloading(false);
  };

  if (!analysisResult) {
    return (
      <div className="d-flex justify-content-center align-items-center min-vh-100">
        <Card style={{ width: '600px' }}>
          <Card.Body>
            <div className="d-flex justify-content-between align-items-center mb-4">
              <Card.Title>Analysis Results</Card.Title>
            </div>
            <div className="text-center">
              <p>No analysis results to display.</p>
              <Button variant="primary" onClick={handleNewUpload}>
                Upload New File
              </Button>
            </div>
          </Card.Body>
        </Card>
      </div>
    );
  }

  // Check if we have the required data
  if (!analysisResult.risk_assessment) {
    return (
      <div className="d-flex justify-content-center align-items-center min-vh-100">
        <Card style={{ width: '600px' }}>
          <Card.Body>
            <div className="d-flex justify-content-between align-items-center mb-4">
              <Card.Title>Analysis Results</Card.Title>
            </div>
            <Alert variant="warning">
              <p>Incomplete analysis results. Please try uploading the file again.</p>
            </Alert>
            <div className="text-center">
              <Button variant="primary" onClick={handleNewUpload}>
                Upload New File
              </Button>
            </div>
          </Card.Body>
        </Card>
      </div>
    );
  }

  return (
    <div className="container py-4">
      <div className="d-flex gap-2 mb-2">
        <Button
          variant={showDebug ? "warning" : "outline-warning"}
          size="sm"
          onClick={() => setShowDebug((prev) => !prev)}
        >
          {showDebug ? "Hide Debug JSON" : "Show Debug JSON"}
        </Button>
        <Button
          variant="outline-info"
          size="sm"
          onClick={() => setShowLogs(true)}
        >
          View Logs
        </Button>
      </div>

      {/* Logs Modal */}
      <Modal show={showLogs} onHide={() => setShowLogs(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Application Logs</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <div style={{ maxHeight: '60vh', overflowY: 'auto' }}>
            <Table striped bordered hover>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Level</th>
                  <th>Message</th>
                  <th>Data</th>
                </tr>
              </thead>
              <tbody>
                {logger.getLogs().map((log, index) => (
                  <tr key={index}>
                    <td>{new Date(log.timestamp).toLocaleTimeString()}</td>
                    <td>
                      <Badge bg={
                        log.level === 'error' ? 'danger' :
                        log.level === 'warn' ? 'warning' :
                        log.level === 'info' ? 'info' : 'secondary'
                      }>
                        {log.level}
                      </Badge>
                    </td>
                    <td>{log.message}</td>
                    <td>
                      <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                        {JSON.stringify(log.data, null, 2)}
                      </pre>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowLogs(false)}>
            Close
          </Button>
          <Button variant="danger" onClick={() => {
            logger.clearLogs();
            setShowLogs(false);
          }}>
            Clear Logs
          </Button>
        </Modal.Footer>
      </Modal>

      {showDebug && (
        <pre style={{ background: '#fff3cd', color: '#856404', padding: '1em', borderRadius: '6px', fontSize: '0.95rem', marginBottom: '1em', whiteSpace: 'pre-wrap' }}>
          {JSON.stringify(analysisResult, null, 2)}
        </pre>
      )}
      {(analysisResult.raw_email || analysisResult.analysis?.raw_email) && (
        <div className="alert alert-info" style={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '0.95rem' }}>
          <h5>Raw Email (Headers & Body)</h5>
          <pre>{analysisResult.raw_email || analysisResult.analysis?.raw_email}</pre>
        </div>
      )}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>Analysis Results</h2>
      </div>

      {/* Basic Information */}
      <Card className="mb-4">
        <Card.Body>
          <h4>Email Information</h4>
          <Table striped bordered hover>
            <tbody>
              <tr>
                <td><strong>Subject</strong></td>
                <td>{analysisResult.subject || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>From</strong></td>
                <td>{analysisResult.from || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>To</strong></td>
                <td>{analysisResult.to || 'N/A'}</td>
              </tr>
            </tbody>
          </Table>
        </Card.Body>
      </Card>

      {/* Risk Assessment */}
      <Card className="mb-4">
        <Card.Body>
          <h4>Risk Assessment</h4>
          <div className="d-flex align-items-center mb-3">
            <h5 className="mb-0 me-3">Risk Score:</h5>
            <Badge bg={getRiskLevelColor(analysisResult.risk_assessment.level)} className="fs-5">
              {analysisResult.risk_assessment.score}/100
            </Badge>
          </div>
          <div>
            <h5>Risk Factors:</h5>
            {analysisResult.risk_assessment.factors?.length > 0 ? (
              <ul>
                {analysisResult.risk_assessment.factors.map((factor, index) => (
                  <li key={index}>{factor}</li>
                ))}
              </ul>
            ) : (
              <Alert variant="success">No risk factors identified.</Alert>
            )}
          </div>
        </Card.Body>
      </Card>

      {/* Authentication Results */}
      <Card className="mb-4">
        <Card.Body>
          <h4>Authentication Results</h4>
          <Table striped bordered hover>
            <tbody>
              <tr>
                <td>SPF</td>
                <td>
                  <Badge bg={analysisResult.spf?.result === 'pass' ? 'success' : 'danger'}>
                    {analysisResult.spf?.result || 'N/A'}
                  </Badge>
                </td>
              </tr>
              <tr>
                <td>DKIM</td>
                <td>
                  <Badge bg={analysisResult.dkim?.result === 'pass' ? 'success' : 'danger'}>
                    {analysisResult.dkim?.result === 'pass' ? 'Pass' : 'Fail'}
                  </Badge>
                </td>
              </tr>
              <tr>
                <td>DMARC</td>
                <td>
                  <Badge bg={analysisResult.dmarc?.result === 'pass' ? 'success' : 'danger'}>
                    {analysisResult.dmarc?.result || 'N/A'}
                  </Badge>
                </td>
              </tr>
            </tbody>
          </Table>
        </Card.Body>
      </Card>

      {/* Threat Intelligence */}
      {renderThreatIntelligence(analysisResult.threat_intelligence)}

      {/* Server Hops */}
      {renderServerHops({ server_hops: analysisResult.server_hops })}

      {/* Attachments */}
      {renderAttachments({ attachments: (analysisResult.attachments?.attachments || []).map(att => ({
        filename: att.filename,
        type: att.content_type || 'N/A',
        size: att.size || null,
        hash: att.hash || null,
        virustotal: att.virustotal || null
      })) })}

      {/* Suspicious HTML Elements */}
      {renderSuspiciousElements({ suspicious_elements: (analysisResult.html_content?.suspicious_elements || []).map(el => ({ type: el, content: 'N/A' })) })}

      {/* Suspicious Language Patterns */}
      {renderSuspiciousPatterns({ suspicious_patterns: (analysisResult.language?.suspicious_patterns || []).map(pat => ({ pattern: pat, context: 'N/A' })), language: analysisResult.language?.language || 'unknown' })}

      {/* Download Buttons */}
      <div className="text-center mt-4">
        {downloadError && <Alert variant="danger">{downloadError}</Alert>}
        <Button
          variant="success"
          className="me-2"
          onClick={() => handleDownload('pdf')}
          disabled={downloading}
        >
          {downloading ? 'Downloading PDF...' : 'Download PDF Report'}
        </Button>
        <Button
          variant="secondary"
          onClick={() => handleDownload('csv')}
          disabled={downloading}
        >
          {downloading ? 'Downloading CSV...' : 'Download CSV Report'}
        </Button>
      </div>

      <div className="text-center mt-4">
        <Button variant="primary" onClick={handleNewUpload}>
          Upload New File
        </Button>
      </div>
    </div>
  );
}

export default ResultDisplay; 