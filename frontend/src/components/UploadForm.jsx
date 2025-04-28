import React, { useState } from 'react';
import { Card, Form, Button, Alert, Spinner } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../services/authService';
import { uploadFile } from '../services/uploadService';
import ResultDisplay from './ResultDisplay';

function UploadForm() {
  const [file, setFile] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile && selectedFile.name.endsWith('.eml')) {
      setFile(selectedFile);
      setError('');
    } else {
      setFile(null);
      setError('Please select a valid .eml file');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const result = await uploadFile(file);
      if (result.success) {
        // Ensure we have the correct data structure
        const analysisData = {
          ...result.data.analysis,
          raw_email: result.data.analysis.raw_email,
          risk_assessment: {
            score: result.data.analysis.risk_assessment?.score || 0,
            level: result.data.analysis.risk_assessment?.level || 'low',
            factors: result.data.analysis.risk_assessment?.factors || []
          },
          spf: {
            result: result.data.analysis.spf?.result || 'unknown',
            status: result.data.analysis.spf?.status || 'error'
          },
          dkim: {
            result: result.data.analysis.dkim?.result || false,
            status: result.data.analysis.dkim?.status || 'error'
          },
          dmarc: {
            result: result.data.analysis.dmarc?.result || 'unknown',
            status: result.data.analysis.dmarc?.status || 'error'
          },
          headers: {
            server_hops: result.data.analysis.headers?.server_hops || [],
            suspicious_headers: result.data.analysis.headers?.suspicious_headers || []
          },
          attachments: {
            attachments: result.data.analysis.attachments?.attachments || []
          },
          html_content: {
            suspicious_elements: result.data.analysis.html_content?.suspicious_elements || []
          },
          language: {
            suspicious_patterns: result.data.analysis.language?.suspicious_patterns || [],
            language: result.data.analysis.language?.language || 'unknown'
          },
          threat_intelligence: {
            threat_data: result.data.analysis.threat_intelligence?.threat_data || {}
          }
        };
        setAnalysis(analysisData);
      } else {
        setError(result.error);
      }
    } catch (error) {
      setError('Failed to upload file');
    }

    setLoading(false);
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const handleNewUpload = () => {
    setAnalysis(null);
    setFile(null);
    setError('');
  };

  if (analysis) {
    return <ResultDisplay analysisResult={analysis} onNewUpload={handleNewUpload} />;
  }

  return (
    <div className="d-flex justify-content-center align-items-center min-vh-100">
      <Card style={{ width: '800px' }}>
        <Card.Body>
          <div className="d-flex justify-content-between align-items-center mb-4">
            <Card.Title>Email Analysis</Card.Title>
            <Button variant="outline-danger" onClick={handleLogout}>
              Logout
            </Button>
          </div>
          {error && <Alert variant="danger">{error}</Alert>}
          <Form onSubmit={handleSubmit}>
            <Form.Group className="mb-3">
              <Form.Label>Select .eml file</Form.Label>
              <Form.Control
                type="file"
                accept=".eml"
                onChange={handleFileChange}
                disabled={loading}
              />
            </Form.Group>
            <Button
              variant="primary"
              type="submit"
              className="w-100"
              disabled={loading || !file}
            >
              {loading ? (
                <>
                  <Spinner
                    as="span"
                    animation="border"
                    size="sm"
                    role="status"
                    aria-hidden="true"
                    className="me-2"
                  />
                  Analyzing...
                </>
              ) : (
                'Analyze Email'
              )}
            </Button>
          </Form>
        </Card.Body>
      </Card>
    </div>
  );
}

export default UploadForm; 