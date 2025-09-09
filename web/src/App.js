import React, { useState, useEffect } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  Grid,
  Paper,
  Box,
  ThemeProvider,
  createTheme,
  CssBaseline
} from '@mui/material';
import { Routes, Route } from 'react-router-dom';
import ScanForm from './components/ScanForm';
import ScanResults from './components/ScanResults';
import ScanProgress from './components/ScanProgress';
import Dashboard from './components/Dashboard';
import Navigation from './components/Navigation';
import { ScanProvider } from './context/ScanContext';
import './App.css';

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00ff41',
    },
    secondary: {
      main: '#ff6b35',
    },
    background: {
      default: '#0a0a0a',
      paper: '#1a1a1a',
    },
    text: {
      primary: '#00ff41',
      secondary: '#ffffff',
    },
  },
  typography: {
    fontFamily: '"Courier New", monospace',
    h4: {
      fontWeight: 700,
      color: '#00ff41',
    },
    h6: {
      fontWeight: 600,
      color: '#00ff41',
    },
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: '1px solid #00ff41',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 0,
          textTransform: 'uppercase',
          fontFamily: '"Courier New", monospace',
        },
      },
    },
  },
});

function App() {
  const [scanHistory, setScanHistory] = useState([]);
  const [currentScan, setCurrentScan] = useState(null);

  useEffect(() => {
    // Load scan history from localStorage
    const savedHistory = localStorage.getItem('omapScanHistory');
    if (savedHistory) {
      setScanHistory(JSON.parse(savedHistory));
    }
  }, []);

  const addScanToHistory = (scan) => {
    const updatedHistory = [scan, ...scanHistory.slice(0, 9)]; // Keep last 10 scans
    setScanHistory(updatedHistory);
    localStorage.setItem('omapScanHistory', JSON.stringify(updatedHistory));
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
          <Box sx={{ flexGrow: 1, minHeight: '100vh', backgroundColor: '#0a0a0a' }}>
            <AppBar position="static" sx={{ backgroundColor: '#000000', borderBottom: '2px solid #00ff41' }}>
              <Toolbar>
                <Typography variant="h6" component="div" sx={{ flexGrow: 1, fontFamily: '"Courier New", monospace' }}>
                  OMAP - Advanced Network Scanner
                </Typography>
                <Typography variant="body2" sx={{ color: '#00ff41' }}>
                  v2.0.0 | Web Interface
                </Typography>
              </Toolbar>
            </AppBar>
            
            <Navigation />
            
            <Container maxWidth="xl" sx={{ mt: 3, mb: 3 }}>
              <Routes>
                <Route path="/" element={
                  <Grid container spacing={3}>
                    <Grid item xs={12} lg={6}>
                      <Paper sx={{ p: 3, mb: 3 }}>
                        <Typography variant="h6" gutterBottom>
                          Network Scanner
                        </Typography>
                        <ScanForm 
                          onScanStart={setCurrentScan}
                          onScanComplete={addScanToHistory}
                        />
                      </Paper>
                      
                      {currentScan && (
                        <Paper sx={{ p: 3 }}>
                          <Typography variant="h6" gutterBottom>
                            Scan Progress
                          </Typography>
                          <ScanProgress scan={currentScan} />
                        </Paper>
                      )}
                    </Grid>
                    
                    <Grid item xs={12} lg={6}>
                      <Paper sx={{ p: 3 }}>
                        <Typography variant="h6" gutterBottom>
                          Scan Results
                        </Typography>
                        <ScanResults scanHistory={scanHistory} />
                      </Paper>
                    </Grid>
                  </Grid>
                } />
                
                <Route path="/dashboard" element={
                  <Dashboard scanHistory={scanHistory} />
                } />
                
                <Route path="/results/:scanId" element={
                  <ScanResults scanHistory={scanHistory} detailed={true} />
                } />
              </Routes>
            </Container>
            
            <Box component="footer" sx={{ 
              mt: 'auto', 
              py: 2, 
              px: 3, 
              backgroundColor: '#000000',
              borderTop: '1px solid #00ff41'
            }}>
              <Typography variant="body2" align="center" sx={{ color: '#00ff41' }}>
                OMAP Web Interface © 2024 | Advanced Network Reconnaissance Tool
              </Typography>
            </Box>
      </Box>
    </ThemeProvider>
  );
}

export default App;