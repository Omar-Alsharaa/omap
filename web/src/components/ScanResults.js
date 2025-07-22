import React, { useState, useMemo } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  Collapse,
  Alert,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  ExpandMore,
  FilterList,
  Download,
  Computer,
  Security,
  NetworkCheck,
  Warning,
  CheckCircle,
  Error,
  Info
} from '@mui/icons-material';
import { useScan } from '../context/ScanContext';

const ScanResults = () => {
  const { scanResults, exportResults } = useScan();
  const [searchTerm, setSearchTerm] = useState('');
  const [serviceFilter, setServiceFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [showFilters, setShowFilters] = useState(false);
  const [expandedHost, setExpandedHost] = useState(null);

  // Group results by host
  const groupedResults = useMemo(() => {
    const grouped = {};
    scanResults.forEach(result => {
      if (!grouped[result.host]) {
        grouped[result.host] = {
          host: result.host,
          ports: [],
          osFingerprint: result.osFingerprint,
          totalPorts: 0,
          openPorts: 0,
          services: new Set()
        };
      }
      
      grouped[result.host].ports.push(result);
      grouped[result.host].totalPorts++;
      
      if (result.status === 'open') {
        grouped[result.host].openPorts++;
      }
      
      if (result.service) {
        grouped[result.host].services.add(result.service);
      }
    });
    
    return Object.values(grouped);
  }, [scanResults]);

  // Filter results
  const filteredResults = useMemo(() => {
    return groupedResults.filter(hostResult => {
      // Search filter
      if (searchTerm && !hostResult.host.toLowerCase().includes(searchTerm.toLowerCase())) {
        return false;
      }
      
      // Service filter
      if (serviceFilter !== 'all') {
        const hasService = hostResult.ports.some(port => 
          port.service && port.service.toLowerCase().includes(serviceFilter.toLowerCase())
        );
        if (!hasService) return false;
      }
      
      // Status filter
      if (statusFilter !== 'all') {
        const hasStatus = hostResult.ports.some(port => port.status === statusFilter);
        if (!hasStatus) return false;
      }
      
      return true;
    });
  }, [groupedResults, searchTerm, serviceFilter, statusFilter]);

  // Get unique services for filter dropdown
  const uniqueServices = useMemo(() => {
    const services = new Set();
    scanResults.forEach(result => {
      if (result.service) {
        services.add(result.service);
      }
    });
    return Array.from(services).sort();
  }, [scanResults]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'open': return 'success';
      case 'closed': return 'error';
      case 'filtered': return 'warning';
      default: return 'default';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'open': return <CheckCircle />;
      case 'closed': return <Error />;
      case 'filtered': return <Warning />;
      default: return <Info />;
    }
  };

  const getRiskLevel = (port, service) => {
    // Simple risk assessment based on common vulnerable services
    const highRiskServices = ['ftp', 'telnet', 'smtp', 'snmp', 'mysql', 'postgresql'];
    const mediumRiskServices = ['ssh', 'http', 'https', 'rdp', 'vnc'];
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995];
    
    if (service && highRiskServices.some(s => service.toLowerCase().includes(s))) {
      return { level: 'high', color: 'error' };
    }
    
    if (service && mediumRiskServices.some(s => service.toLowerCase().includes(s))) {
      return { level: 'medium', color: 'warning' };
    }
    
    if (commonPorts.includes(port)) {
      return { level: 'low', color: 'info' };
    }
    
    return { level: 'info', color: 'default' };
  };

  const handleExport = (format) => {
    exportResults(format);
  };

  if (scanResults.length === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <NetworkCheck sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
        <Typography variant="h6" color="text.secondary">
          No scan results available
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Start a scan to see results here
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ width: '100%' }}>
      {/* Header with stats */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" gutterBottom>
          Scan Results
        </Typography>
        
        <Grid container spacing={2} sx={{ mb: 2 }}>
          <Grid item xs={6} md={3}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Computer color="primary" sx={{ fontSize: 30, mb: 1 }} />
                <Typography variant="h6">{filteredResults.length}</Typography>
                <Typography variant="body2" color="text.secondary">
                  Hosts
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={6} md={3}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <CheckCircle color="success" sx={{ fontSize: 30, mb: 1 }} />
                <Typography variant="h6">
                  {filteredResults.reduce((sum, host) => sum + host.openPorts, 0)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Open Ports
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={6} md={3}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Security color="warning" sx={{ fontSize: 30, mb: 1 }} />
                <Typography variant="h6">{uniqueServices.length}</Typography>
                <Typography variant="body2" color="text.secondary">
                  Services
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={6} md={3}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <NetworkCheck color="info" sx={{ fontSize: 30, mb: 1 }} />
                <Typography variant="h6">{scanResults.length}</Typography>
                <Typography variant="body2" color="text.secondary">
                  Total Ports
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>

      {/* Filters and Export */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Button
            startIcon={<FilterList />}
            onClick={() => setShowFilters(!showFilters)}
            variant="outlined"
          >
            Filters
          </Button>
          
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              startIcon={<Download />}
              onClick={() => handleExport('json')}
              size="small"
            >
              JSON
            </Button>
            <Button
              startIcon={<Download />}
              onClick={() => handleExport('csv')}
              size="small"
            >
              CSV
            </Button>
            <Button
              startIcon={<Download />}
              onClick={() => handleExport('html')}
              size="small"
            >
              HTML
            </Button>
          </Box>
        </Box>
        
        <Collapse in={showFilters}>
          <Paper sx={{ p: 2, mb: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="Search Hosts"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Enter hostname or IP"
                  size="small"
                />
              </Grid>
              
              <Grid item xs={12} md={4}>
                <FormControl fullWidth size="small">
                  <InputLabel>Service</InputLabel>
                  <Select
                    value={serviceFilter}
                    onChange={(e) => setServiceFilter(e.target.value)}
                    label="Service"
                  >
                    <MenuItem value="all">All Services</MenuItem>
                    {uniqueServices.map(service => (
                      <MenuItem key={service} value={service}>
                        {service}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              
              <Grid item xs={12} md={4}>
                <FormControl fullWidth size="small">
                  <InputLabel>Status</InputLabel>
                  <Select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    label="Status"
                  >
                    <MenuItem value="all">All Status</MenuItem>
                    <MenuItem value="open">Open</MenuItem>
                    <MenuItem value="closed">Closed</MenuItem>
                    <MenuItem value="filtered">Filtered</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </Paper>
        </Collapse>
      </Box>

      {/* Results */}
      <Box>
        {filteredResults.map((hostResult, index) => (
          <Accordion
            key={hostResult.host}
            expanded={expandedHost === hostResult.host}
            onChange={() => setExpandedHost(
              expandedHost === hostResult.host ? null : hostResult.host
            )}
            sx={{ mb: 1 }}
          >
            <AccordionSummary expandIcon={<ExpandMore />}>
              <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                <Computer sx={{ mr: 2, color: 'primary.main' }} />
                <Box sx={{ flexGrow: 1 }}>
                  <Typography variant="h6">{hostResult.host}</Typography>
                  <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                    <Chip
                      size="small"
                      label={`${hostResult.openPorts} open`}
                      color="success"
                      variant="outlined"
                    />
                    <Chip
                      size="small"
                      label={`${hostResult.totalPorts} total`}
                      color="primary"
                      variant="outlined"
                    />
                    <Chip
                      size="small"
                      label={`${hostResult.services.size} services`}
                      color="secondary"
                      variant="outlined"
                    />
                  </Box>
                </Box>
                {hostResult.osFingerprint && (
                  <Tooltip title={`OS: ${hostResult.osFingerprint.os}`}>
                    <Chip
                      size="small"
                      label={hostResult.osFingerprint.os}
                      color="info"
                      sx={{ mr: 2 }}
                    />
                  </Tooltip>
                )}
              </Box>
            </AccordionSummary>
            
            <AccordionDetails>
              {hostResult.osFingerprint && (
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="subtitle2">OS Detection</Typography>
                  <Typography variant="body2">
                    {hostResult.osFingerprint.os} (Confidence: {hostResult.osFingerprint.confidence}%)
                  </Typography>
                  {hostResult.osFingerprint.details && (
                    <Typography variant="caption" display="block">
                      {hostResult.osFingerprint.details}
                    </Typography>
                  )}
                </Alert>
              )}
              
              <TableContainer component={Paper}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Port</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Service</TableCell>
                      <TableCell>Version</TableCell>
                      <TableCell>Banner</TableCell>
                      <TableCell>Risk</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {hostResult.ports
                      .filter(port => statusFilter === 'all' || port.status === statusFilter)
                      .map((port, portIndex) => {
                        const risk = getRiskLevel(port.port, port.service);
                        return (
                          <TableRow key={portIndex}>
                            <TableCell>
                              <Typography variant="body2" fontWeight="bold">
                                {port.port}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Chip
                                size="small"
                                icon={getStatusIcon(port.status)}
                                label={port.status}
                                color={getStatusColor(port.status)}
                                variant="outlined"
                              />
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">
                                {port.service || 'Unknown'}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">
                                {port.version || '-'}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography
                                variant="caption"
                                sx={{
                                  maxWidth: 200,
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap',
                                  display: 'block'
                                }}
                              >
                                {port.banner || '-'}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Chip
                                size="small"
                                label={risk.level}
                                color={risk.color}
                                variant="outlined"
                              />
                            </TableCell>
                          </TableRow>
                        );
                      })}
                  </TableBody>
                </Table>
              </TableContainer>
              
              {/* Plugin Results */}
              {hostResult.ports.some(port => port.pluginResults && port.pluginResults.length > 0) && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Plugin Results
                  </Typography>
                  {hostResult.ports
                    .filter(port => port.pluginResults && port.pluginResults.length > 0)
                    .map((port, portIndex) => (
                      <Box key={portIndex} sx={{ mb: 1 }}>
                        <Typography variant="caption" color="text.secondary">
                          Port {port.port}:
                        </Typography>
                        {port.pluginResults.map((plugin, pluginIndex) => (
                          <Alert
                            key={pluginIndex}
                            severity={plugin.severity || 'info'}
                            sx={{ mt: 1 }}
                          >
                            <Typography variant="subtitle2">
                              {plugin.name}
                            </Typography>
                            <Typography variant="body2">
                              {plugin.description}
                            </Typography>
                            {plugin.details && (
                              <Typography variant="caption" display="block">
                                {plugin.details}
                              </Typography>
                            )}
                          </Alert>
                        ))}
                      </Box>
                    ))}
                </Box>
              )}
            </AccordionDetails>
          </Accordion>
        ))}
      </Box>
      
      {filteredResults.length === 0 && (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <Typography variant="body1" color="text.secondary">
            No results match the current filters
          </Typography>
        </Box>
      )}
    </Box>
  );
};

export default ScanResults;