import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Container } from 'react-bootstrap';
import Login from './components/Login';
import Register from './components/Register';
import UploadForm from './components/UploadForm';
import ResultDisplay from './components/ResultDisplay';
import { AuthProvider, useAuth } from './services/authService';
import 'bootstrap/dist/css/bootstrap.min.css';
import { AppBar, Toolbar, Typography, Button, Box } from '@mui/material';
import EmailAnalysis from './components/EmailAnalysis';
import { Link } from 'react-router-dom';

function NavBarButtons() {
  const { user } = useAuth();
  return (
    <>
      <Button color="inherit" component={Link} to="/">
        Home
      </Button>
      <Button color="inherit" component={Link} to="/analyze">
        Analyze Email
      </Button>
      <Button color="inherit" component={Link} to="/login">
        Login
      </Button>
      <Button color="inherit" component={Link} to="/register">
        Register
      </Button>
    </>
  );
}

function App() {
  return (
    <AuthProvider>
      <Router>
        <Box sx={{ flexGrow: 1 }}>
          <AppBar position="static">
            <Toolbar>
              <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
                Email Phishing Detector
              </Typography>
              <NavBarButtons />
            </Toolbar>
          </AppBar>

          <Container className="py-5">
            <Routes>
              <Route path="/" element={
                <Box sx={{ textAlign: 'center', mt: 4 }}>
                  <Typography variant="h4" gutterBottom>
                    Welcome to Email Phishing Detector
                  </Typography>
                  <Typography variant="body1" paragraph>
                    Upload an email file (.eml) to analyze it for potential phishing attempts.
                  </Typography>
                  <Button
                    variant="contained"
                    color="primary"
                    component={Link}
                    to="/analyze"
                  >
                    Start Analysis
                  </Button>
                </Box>
              } />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/upload" element={<UploadForm />} />
              <Route path="/result" element={<ResultDisplay />} />
              <Route path="/analyze" element={<EmailAnalysis />} />
              <Route path="/" element={<Navigate to="/login" replace />} />
            </Routes>
          </Container>
        </Box>
      </Router>
    </AuthProvider>
  );
}

export default App; 