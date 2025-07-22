import React, { useState } from 'react';
import {
  Box,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Switch,
  Grid,
  Chip,
  Typography,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  PlayArrow,
  Stop,
  ExpandMore,
  Settings
} from '@mui/icons-material';
import { useScan } from '../context/ScanContext';

const ScanForm = ({ onScanStart, onScanComplete }) => {
  const { isScanning, startScan, stopScan, error, clearError } = useScan();
  
  const [formData, setFormData] = useState({
    targets: '127.0.0.1',
    ports: 'top-100',
    workers: 100,
    timeout: 3,
    rateLimit: 0,
    connectOnly: false,
    enablePlugins: false,
    pluginDir: './plugins/examples',
    osDetection: false,
    serviceDetection: false,
    verbose: false,
    outputFormat: 'json'
  });

  const [customPorts, setCustomPorts] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const portPresets = {
    'top-100': 'Top 100 most common ports',
    'top-1000': 'Top 1000 most common ports',
    'common': 'Common service ports',
    'web': 'Web application ports (80, 443, 8080, etc.)',
    'database': 'Database ports (3306, 5432, 1433, etc.)',
    'custom': 'Custom port specification'
  };

  const handleInputChange = (field) => (event) => {
    const value = event.target.type === 'checkbox' ? event.target.checked : event.target.value;
    setFormData(prev => ({ ...prev, [field]: value }));
    
    if (error) clearError();
  };

  const handlePortPresetChange = (event) => {
    const preset = event.target.value;
    setFormData(prev => ({ ...prev, ports: preset }));
    
    if (preset === 'custom') {
      setCustomPorts('');
    }
  };

  const handleCustomPortsChange = (event) => {
    setCustomPorts(event.target.value);
    setFormData(prev => ({ ...prev, ports: event.target.value }));
  };

  const validateForm = () => {
    if (!formData.targets.trim()) {
      return 'Target is required';
    }
    
    if (formData.ports === 'custom' && !customPorts.trim()) {
      return 'Custom ports specification is required';
    }
    
    if (formData.workers < 1 || formData.workers > 1000) {
      return 'Workers must be between 1 and 1000';
    }
    
    if (formData.timeout < 1 || formData.timeout > 60) {
      return 'Timeout must be between 1 and 60 seconds';
    }
    
    return null;
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    
    const validationError = validateForm();
    if (validationError) {
      alert(validationError);
      return;
    }

    const scanConfig = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      ...formData,
      ports: formData.ports === 'custom' ? customPorts : formData.ports
    };

    try {
      await startScan(scanConfig);
      if (onScanStart) {
        onScanStart(scanConfig);
      }
    } catch (err) {
      console.error('Failed to start scan:', err);
    }
  };

  const handleStop = () => {
    stopScan();
  };

  const getTargetExamples = () => {
    return [
      '192.168.1.1',
      'example.com',
      '192.168.1.0/24',
      '192.168.1.1-10',
      '192.168.1.1,10.0.0.1'
    ];
  };

  return (
    <Box component="form" onSubmit={handleSubmit} sx={{ width: '100%' }}>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={clearError}>
          {error}
        </Alert>
      )}
      
      <Grid container spacing={3}>
        {/* Basic Configuration */}
        <Grid item xs={12}>
          <TextField
            fullWidth
            label="Targets"
            value={formData.targets}
            onChange={handleInputChange('targets')}
            placeholder="192.168.1.1, example.com, 192.168.1.0/24"
            helperText="IP addresses, hostnames, CIDR notation, or ranges"
            required
            disabled={isScanning}
          />
        </Grid>
        
        <Grid item xs={12} md={8}>
          <FormControl fullWidth>
            <InputLabel>Port Specification</InputLabel>
            <Select
              value={formData.ports === customPorts && customPorts ? 'custom' : formData.ports}
              onChange={handlePortPresetChange}
              disabled={isScanning}
            >
              {Object.entries(portPresets).map(([value, label]) => (
                <MenuItem key={value} value={value}>
                  {label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <TextField
            fullWidth
            label="Workers"
            type="number"
            value={formData.workers}
            onChange={handleInputChange('workers')}
            inputProps={{ min: 1, max: 1000 }}
            disabled={isScanning}
          />
        </Grid>
        
        {(formData.ports === 'custom' || customPorts) && (
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="Custom Ports"
              value={customPorts}
              onChange={handleCustomPortsChange}
              placeholder="22,80,443 or 1-1000 or 22,80-90,443"
              helperText="Comma-separated ports, ranges, or mixed"
              disabled={isScanning}
            />
          </Grid>
        )}
        
        {/* Quick Options */}
        <Grid item xs={12}>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={formData.osDetection}
                  onChange={handleInputChange('osDetection')}
                  disabled={isScanning}
                />
              }
              label="OS Detection"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={formData.serviceDetection}
                  onChange={handleInputChange('serviceDetection')}
                  disabled={isScanning}
                />
              }
              label="Service Detection"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={formData.enablePlugins}
                  onChange={handleInputChange('enablePlugins')}
                  disabled={isScanning}
                />
              }
              label="Enable Plugins"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={formData.verbose}
                  onChange={handleInputChange('verbose')}
                  disabled={isScanning}
                />
              }
              label="Verbose Output"
            />
          </Box>
        </Grid>
        
        {/* Advanced Options */}
        <Grid item xs={12}>
          <Accordion expanded={showAdvanced} onChange={() => setShowAdvanced(!showAdvanced)}>
            <AccordionSummary expandIcon={<ExpandMore />}>
              <Settings sx={{ mr: 1 }} />
              <Typography>Advanced Options</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Timeout (seconds)"
                    type="number"
                    value={formData.timeout}
                    onChange={handleInputChange('timeout')}
                    inputProps={{ min: 1, max: 60 }}
                    disabled={isScanning}
                  />
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Rate Limit (ms)"
                    type="number"
                    value={formData.rateLimit}
                    onChange={handleInputChange('rateLimit')}
                    inputProps={{ min: 0 }}
                    helperText="0 = no rate limiting"
                    disabled={isScanning}
                  />
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Plugin Directory"
                    value={formData.pluginDir}
                    onChange={handleInputChange('pluginDir')}
                    disabled={isScanning || !formData.enablePlugins}
                  />
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth>
                    <InputLabel>Output Format</InputLabel>
                    <Select
                      value={formData.outputFormat}
                      onChange={handleInputChange('outputFormat')}
                      disabled={isScanning}
                    >
                      <MenuItem value="json">JSON</MenuItem>
                      <MenuItem value="xml">XML</MenuItem>
                      <MenuItem value="csv">CSV</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                
                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={formData.connectOnly}
                        onChange={handleInputChange('connectOnly')}
                        disabled={isScanning}
                      />
                    }
                    label="Connect Only (Skip Banner Grabbing)"
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        </Grid>
        
        {/* Target Examples */}
        <Grid item xs={12}>
          <Typography variant="body2" sx={{ mb: 1 }}>Target Examples:</Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
            {getTargetExamples().map((example, index) => (
              <Chip
                key={index}
                label={example}
                size="small"
                onClick={() => setFormData(prev => ({ ...prev, targets: example }))}
                sx={{ cursor: 'pointer' }}
                disabled={isScanning}
              />
            ))}
          </Box>
        </Grid>
        
        {/* Action Buttons */}
        <Grid item xs={12}>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
            {isScanning ? (
              <Button
                variant="contained"
                color="error"
                startIcon={<Stop />}
                onClick={handleStop}
                size="large"
              >
                Stop Scan
              </Button>
            ) : (
              <Button
                type="submit"
                variant="contained"
                color="primary"
                startIcon={<PlayArrow />}
                size="large"
              >
                Start Scan
              </Button>
            )}
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ScanForm;