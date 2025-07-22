import React, { useState, useEffect } from 'react';
import {
  Box,
  LinearProgress,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  CircularProgress
} from '@mui/material';
import {
  Timer,
  Computer,
  Security,
  NetworkCheck,
  CheckCircle,
  Error,
  Speed
} from '@mui/icons-material';
import { useScan } from '../context/ScanContext';

const ScanProgress = ({ scan }) => {
  const { scanProgress, scanStats, scanResults, isScanning } = useScan();
  const [elapsedTime, setElapsedTime] = useState(0);
  const [recentResults, setRecentResults] = useState([]);

  useEffect(() => {
    let interval;
    if (isScanning && scanStats.startTime) {
      interval = setInterval(() => {
        const elapsed = Math.floor((new Date() - new Date(scanStats.startTime)) / 1000);
        setElapsedTime(elapsed);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isScanning, scanStats.startTime]);

  useEffect(() => {
    // Keep track of recent results (last 10)
    if (scanResults.length > 0) {
      setRecentResults(prev => {
        const newResults = scanResults.slice(-10);
        return newResults;
      });
    }
  }, [scanResults]);

  const formatTime = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
  };

  const calculateETA = () => {
    if (!scanStats.scannedPorts || !scanStats.totalPorts || elapsedTime < 10) {
      return 'Calculating...';
    }
    
    const progress = scanStats.scannedPorts / scanStats.totalPorts;
    const estimatedTotal = elapsedTime / progress;
    const remaining = Math.max(0, estimatedTotal - elapsedTime);
    
    return formatTime(Math.floor(remaining));
  };

  const getProgressColor = () => {
    if (scanProgress < 25) return 'error';
    if (scanProgress < 75) return 'warning';
    return 'success';
  };

  const getScanSpeed = () => {
    if (elapsedTime === 0) return 0;
    return Math.floor(scanStats.scannedPorts / elapsedTime);
  };

  if (!isScanning && !scan) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <Typography variant="body1" color="text.secondary">
          No active scan
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ width: '100%' }}>
      {/* Main Progress Bar */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
          <Typography variant="h6">
            {isScanning ? 'Scanning in Progress' : 'Scan Complete'}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {Math.round(scanProgress)}%
          </Typography>
        </Box>
        
        <LinearProgress
          variant="determinate"
          value={scanProgress}
          color={getProgressColor()}
          sx={{ height: 8, borderRadius: 4 }}
        />
        
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 1 }}>
          <Typography variant="body2" color="text.secondary">
            Target: {scan?.targets || 'Unknown'}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Ports: {scan?.ports || 'Unknown'}
          </Typography>
        </Box>
      </Box>

      {/* Statistics Grid */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={6} md={3}>
          <Card sx={{ textAlign: 'center' }}>
            <CardContent sx={{ py: 2 }}>
              <Timer color="primary" sx={{ fontSize: 30, mb: 1 }} />
              <Typography variant="h6">{formatTime(elapsedTime)}</Typography>
              <Typography variant="body2" color="text.secondary">
                Elapsed
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={6} md={3}>
          <Card sx={{ textAlign: 'center' }}>
            <CardContent sx={{ py: 2 }}>
              <Speed color="primary" sx={{ fontSize: 30, mb: 1 }} />
              <Typography variant="h6">{getScanSpeed()}</Typography>
              <Typography variant="body2" color="text.secondary">
                Ports/sec
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={6} md={3}>
          <Card sx={{ textAlign: 'center' }}>
            <CardContent sx={{ py: 2 }}>
              <CheckCircle color="success" sx={{ fontSize: 30, mb: 1 }} />
              <Typography variant="h6">{scanStats.openPorts || 0}</Typography>
              <Typography variant="body2" color="text.secondary">
                Open Ports
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={6} md={3}>
          <Card sx={{ textAlign: 'center' }}>
            <CardContent sx={{ py: 2 }}>
              <Timer color="warning" sx={{ fontSize: 30, mb: 1 }} />
              <Typography variant="h6">{calculateETA()}</Typography>
              <Typography variant="body2" color="text.secondary">
                ETA
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Detailed Progress */}
      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Scan Progress
              </Typography>
              
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">Hosts</Typography>
                  <Typography variant="body2">
                    {scanStats.scannedHosts || 0} / {scanStats.totalHosts || 0}
                  </Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={scanStats.totalHosts ? (scanStats.scannedHosts / scanStats.totalHosts) * 100 : 0}
                  sx={{ height: 6, borderRadius: 3 }}
                />
              </Box>
              
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">Ports</Typography>
                  <Typography variant="body2">
                    {scanStats.scannedPorts || 0} / {scanStats.totalPorts || 0}
                  </Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={scanStats.totalPorts ? (scanStats.scannedPorts / scanStats.totalPorts) * 100 : 0}
                  sx={{ height: 6, borderRadius: 3 }}
                />
              </Box>
              
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                <Chip
                  icon={<Computer />}
                  label={`${scanStats.totalHosts || 0} Hosts`}
                  size="small"
                  color="primary"
                  variant="outlined"
                />
                <Chip
                  icon={<NetworkCheck />}
                  label={`${scanStats.totalPorts || 0} Ports`}
                  size="small"
                  color="primary"
                  variant="outlined"
                />
                {scan?.osDetection && (
                  <Chip
                    icon={<Security />}
                    label="OS Detection"
                    size="small"
                    color="secondary"
                    variant="outlined"
                  />
                )}
                {scan?.serviceDetection && (
                  <Chip
                    icon={<Security />}
                    label="Service Detection"
                    size="small"
                    color="secondary"
                    variant="outlined"
                  />
                )}
                {scan?.enablePlugins && (
                  <Chip
                    icon={<Security />}
                    label="Plugins Enabled"
                    size="small"
                    color="secondary"
                    variant="outlined"
                  />
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Discoveries
              </Typography>
              
              {recentResults.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 2 }}>
                  {isScanning ? (
                    <>
                      <CircularProgress size={24} sx={{ mb: 1 }} />
                      <Typography variant="body2" color="text.secondary">
                        Scanning for open ports...
                      </Typography>
                    </>
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      No results yet
                    </Typography>
                  )}
                </Box>
              ) : (
                <List dense sx={{ maxHeight: 200, overflow: 'auto' }}>
                  {recentResults.slice().reverse().map((result, index) => (
                    <React.Fragment key={index}>
                      <ListItem>
                        <ListItemIcon>
                          <CheckCircle color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText
                          primary={`${result.host}:${result.port}`}
                          secondary={`${result.service || 'Unknown'} - ${result.banner || 'No banner'}`}
                          primaryTypographyProps={{ variant: 'body2' }}
                          secondaryTypographyProps={{ variant: 'caption' }}
                        />
                      </ListItem>
                      {index < recentResults.length - 1 && <Divider />}
                    </React.Fragment>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ScanProgress;