import React, { useState } from 'react';
import axios from 'axios';
import { useAuth } from '../services/authService';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Button,
  Card,
  CardContent,
  Typography,
  CircularProgress,
  Alert,
  Divider,
  List,
  ListItem,
  ListItemText,
  Chip,
} from '@mui/material';
import { styled } from '@mui/material/styles';

const StyledCard = styled(Card)(({ theme }) => ({
  margin: theme.spacing(2),
  maxWidth: 800,
  marginLeft: 'auto',
  marginRight: 'auto',
}));

const RiskScore = styled(Box)(({ score }) => ({
  width: 100,
  height: 100,
  borderRadius: '50%',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  backgroundColor: score <= 30 ? '#4caf50' : score <= 70 ? '#ff9800' : '#f44336',
  color: 'white',
  fontSize: '24px',
  fontWeight: 'bold',
}));

const EmailAnalysis = () => {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [results, setResults] = useState(null);
  const { user } = useAuth();
  const navigate = useNavigate();

  // Debug: log results whenever the component renders
  console.log('Component render, results:', results);

  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
    setError(null);
    setResults(null);
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please select a file first');
      return;
    }

    if (!user) {
      setError('Please log in to analyze emails');
      navigate('/login');
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('http://localhost:5000/uploads/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'Authorization': `Bearer ${token}`
        },
      });
      setResults(response.data.analysis);
      // Debug: log the analysis result after setting state
      console.log('API response analysis:', response.data.analysis);
    } catch (err) {
      if (err.response?.status === 401) {
        setError('Your session has expired. Please log in again.');
        navigate('/login');
      } else {
        setError(err.response?.data?.error || 'An error occurred during analysis');
      }
    } finally {
      setLoading(false);
    }
  };

  const renderResults = () => {
    if (!results) return null;

    // Debug: log the results object to check for raw_email
    console.log('Analysis Results:', results);

    return (
      <Box>
        {/* Debug: Show the entire results object as JSON */}
        <Box sx={{ bgcolor: '#fff3cd', color: '#856404', p: 2, mb: 2, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.95rem' }}>
          <Typography variant="h6">Debug: Raw Results Object</Typography>
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{JSON.stringify(results, null, 2)}</pre>
        </Box>

        <Typography variant="h5" gutterBottom>
          Email Information
        </Typography>
        <List>
          <ListItem>
            <ListItemText primary="Subject" secondary={results.email_info.subject} />
          </ListItem>
          <ListItem>
            <ListItemText primary="From" secondary={results.email_info.from} />
          </ListItem>
          <ListItem>
            <ListItemText primary="To" secondary={results.email_info.to} />
          </ListItem>
        </List>

        <Divider sx={{ my: 2 }} />

        <Typography variant="h5" gutterBottom>
          Risk Assessment
        </Typography>
        <Box display="flex" alignItems="center" mb={2}>
          <RiskScore score={results.risk_assessment.risk_score}>
            {results.risk_assessment.risk_score}
          </RiskScore>
          <Box ml={2}>
            <Typography variant="h6">Risk Score</Typography>
            <Typography variant="body2" color="textSecondary">
              {results.risk_assessment.risk_factors.length > 0
                ? 'Risk factors identified'
                : 'No risk factors identified'}
            </Typography>
          </Box>
        </Box>

        {results.risk_assessment.risk_factors.length > 0 && (
          <List>
            {results.risk_assessment.risk_factors.map((factor, index) => (
              <ListItem key={index}>
                <ListItemText primary={factor} />
              </ListItem>
            ))}
          </List>
        )}

        <Divider sx={{ my: 2 }} />

        <Typography variant="h5" gutterBottom>
          Authentication Results
        </Typography>
        <Box display="flex" gap={2}>
          <Chip
            label={`SPF: ${results.authentication_results.SPF}`}
            color={results.authentication_results.SPF === 'Pass' ? 'success' : 'error'}
          />
          <Chip
            label={`DKIM: ${results.authentication_results.DKIM}`}
            color={results.authentication_results.DKIM === 'Pass' ? 'success' : 'error'}
          />
          <Chip
            label={`DMARC: ${results.authentication_results.DMARC}`}
            color={results.authentication_results.DMARC === 'Pass' ? 'success' : 'error'}
          />
        </Box>

        <Divider sx={{ my: 2 }} />

        <Typography variant="h5" gutterBottom>
          Attachments
        </Typography>
        {results.attachments.length > 0 ? (
          <List>
            {results.attachments.map((attachment, index) => (
              <ListItem key={index}>
                <ListItemText
                  primary={attachment.name}
                  secondary={`Type: ${attachment.type}`}
                />
              </ListItem>
            ))}
          </List>
        ) : (
          <Typography>No attachments found</Typography>
        )}

        <Divider sx={{ my: 2 }} />

        <Typography variant="h5" gutterBottom>
          Suspicious Elements
        </Typography>
        {results.suspicious_html.length > 0 && (
          <>
            <Typography variant="h6">HTML Elements</Typography>
            <List>
              {results.suspicious_html.map((element, index) => (
                <ListItem key={index}>
                  <ListItemText primary={element} />
                </ListItem>
              ))}
            </List>
          </>
        )}

        {results.suspicious_language.length > 0 && (
          <>
            <Typography variant="h6">Language Patterns</Typography>
            <List>
              {results.suspicious_language.map((pattern, index) => (
                <ListItem key={index}>
                  <ListItemText primary={pattern} />
                </ListItem>
              ))}
            </List>
          </>
        )}

        {/* Raw Email Section */}
        {(results?.raw_email || results?.analysis?.raw_email) && (
          <>
            <Divider sx={{ my: 2 }} />
            <Typography variant="h5" gutterBottom>
              Raw Email (Headers & Body)
            </Typography>
            <Box sx={{ whiteSpace: 'pre-wrap', bgcolor: '#f5f5f5', p: 2, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.95rem', maxHeight: 400, overflow: 'auto' }}>
              {results.raw_email || results.analysis?.raw_email}
            </Box>
          </>
        )}
      </Box>
    );
  };

  return (
    <StyledCard>
      <CardContent>
        <Typography variant="h4" gutterBottom>
          Email Analysis
        </Typography>

        {/* Always show raw_email if present */}
        {(results?.raw_email || results?.analysis?.raw_email) && (
          <Box sx={{ bgcolor: '#e3f2fd', color: '#0d47a1', p: 2, mb: 2, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.95rem' }}>
            <Typography variant="h6">Raw Email (Headers & Body)</Typography>
            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {results.raw_email || results.analysis?.raw_email}
            </pre>
          </Box>
        )}

        <Box mb={3}>
          <input
            accept=".eml"
            style={{ display: 'none' }}
            id="email-file"
            type="file"
            onChange={handleFileChange}
          />
          <label htmlFor="email-file">
            <Button variant="contained" component="span">
              Select Email File
            </Button>
          </label>
          {file && (
            <Typography variant="body2" sx={{ mt: 1 }}>
              Selected file: {file.name}
            </Typography>
          )}
        </Box>

        <Button
          variant="contained"
          color="primary"
          onClick={handleAnalyze}
          disabled={!file || loading}
          sx={{ mb: 2 }}
        >
          {loading ? <CircularProgress size={24} /> : 'Analyze Email'}
        </Button>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {renderResults()}
      </CardContent>
    </StyledCard>
  );
};

export default EmailAnalysis; 