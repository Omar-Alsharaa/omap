import React, { useState, useMemo } from 'react';
import {
  Box,
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
  LinearProgress,
  IconButton,
  Menu,
  MenuItem,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow
} from '@mui/material';
import {
  Computer,
  Security,
  NetworkCheck,
  Timeline,
  TrendingUp,
  Warning,
  CheckCircle,
  Error,
  MoreVert,
  Delete,
  Download,
  History,
  Assessment
} from '@mui/icons-material';
import {
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';
import { useScan } from '../context/ScanContext';

const Dashboard = () => {
  const { scanHistory, deleteScanFromHistory, exportResults } = useScan();
  const [menuAnchor, setMenuAnchor] = useState(null);
  const [selectedScan, setSelectedScan] = useState(null);

  // Calculate dashboard statistics
  const stats = useMemo(() => {
    if (scanHistory.length === 0) {
      return {
        totalScans: 0,
        totalHosts: 0,
        totalPorts: 0,
        openPorts: 0,
        uniqueServices: 0,
        avgScanTime: 0,
        successRate: 0
      };
    }

    const totalScans = scanHistory.length;
    const completedScans = scanHistory.filter(scan => scan.status === 'completed');
    const totalHosts = scanHistory.reduce((sum, scan) => sum + (scan.stats?.totalHosts || 0), 0);
    const totalPorts = scanHistory.reduce((sum, scan) => sum + (scan.stats?.totalPorts || 0), 0);
    const openPorts = scanHistory.reduce((sum, scan) => sum + (scan.stats?.openPorts || 0), 0);
    
    const allServices = new Set();
    scanHistory.forEach(scan => {
      if (scan.results) {
        scan.results.forEach(result => {
          if (result.service) {
            allServices.add(result.service);
          }
        });
      }
    });
    
    const avgScanTime = completedScans.length > 0 
      ? completedScans.reduce((sum, scan) => sum + (scan.duration || 0), 0) / completedScans.length
      : 0;
    
    const successRate = totalScans > 0 ? (completedScans.length / totalScans) * 100 : 0;

    return {
      totalScans,
      totalHosts,
      totalPorts,
      openPorts,
      uniqueServices: allServices.size,
      avgScanTime: Math.round(avgScanTime),
      successRate: Math.round(successRate)
    };
  }, [scanHistory]);

  // Prepare chart data
  const chartData = useMemo(() => {
    const last30Days = scanHistory
      .filter(scan => {
        const scanDate = new Date(scan.timestamp);
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        return scanDate >= thirtyDaysAgo;
      })
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    const dailyStats = {};
    
    last30Days.forEach(scan => {
      const date = new Date(scan.timestamp).toISOString().split('T')[0];
      if (!dailyStats[date]) {
        dailyStats[date] = {
          date,
          scans: 0,
          hosts: 0,
          openPorts: 0,
          totalPorts: 0
        };
      }
      
      dailyStats[date].scans++;
      dailyStats[date].hosts += scan.stats?.totalHosts || 0;
      dailyStats[date].openPorts += scan.stats?.openPorts || 0;
      dailyStats[date].totalPorts += scan.stats?.totalPorts || 0;
    });

    return Object.values(dailyStats);
  }, [scanHistory]);

  // Service distribution data
  const serviceData = useMemo(() => {
    const services = {};
    
    scanHistory.forEach(scan => {
      if (scan.results) {
        scan.results.forEach(result => {
          if (result.service && result.status === 'open') {
            services[result.service] = (services[result.service] || 0) + 1;
          }
        });
      }
    });

    return Object.entries(services)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [scanHistory]);

  const handleMenuOpen = (event, scan) => {
    setMenuAnchor(event.currentTarget);
    setSelectedScan(scan);
  };

  const handleMenuClose = () => {
    setMenuAnchor(null);
    setSelectedScan(null);
  };

  const handleDeleteScan = () => {
    if (selectedScan) {
      deleteScanFromHistory(selectedScan.id);
    }
    handleMenuClose();
  };

  const handleExportScan = (format) => {
    if (selectedScan && selectedScan.results) {
      exportResults(format, selectedScan.results);
    }
    handleMenuClose();
  };

  const formatDuration = (seconds) => {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'success';
      case 'running': return 'primary';
      case 'failed': return 'error';
      case 'cancelled': return 'warning';
      default: return 'default';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle />;
      case 'running': return <Timeline />;
      case 'failed': return <Error />;
      case 'cancelled': return <Warning />;
      default: return <History />;
    }
  };

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D'];

  return (
    <Box sx={{ width: '100%' }}>
      {/* Header */}
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      
      {scanHistory.length === 0 ? (
        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="h6">Welcome to OMAP Dashboard</Typography>
          <Typography variant="body2">
            Start your first scan to see statistics and analytics here.
          </Typography>
        </Alert>
      ) : (
        <>
          {/* Statistics Cards */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Assessment color="primary" sx={{ fontSize: 40, mb: 1 }} />
                  <Typography variant="h4">{stats.totalScans}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Scans
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Computer color="info" sx={{ fontSize: 40, mb: 1 }} />
                  <Typography variant="h4">{stats.totalHosts}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Hosts Scanned
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent sx={{ textAlign: 'center' }}>
                  <CheckCircle color="success" sx={{ fontSize: 40, mb: 1 }} />
                  <Typography variant="h4">{stats.openPorts}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Open Ports
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Security color="warning" sx={{ fontSize: 40, mb: 1 }} />
                  <Typography variant="h4">{stats.uniqueServices}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Services Found
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Charts */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} lg={8}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Scan Activity (Last 30 Days)
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={chartData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="date" />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      <Area
                        type="monotone"
                        dataKey="scans"
                        stackId="1"
                        stroke="#8884d8"
                        fill="#8884d8"
                        name="Scans"
                      />
                      <Area
                        type="monotone"
                        dataKey="openPorts"
                        stackId="2"
                        stroke="#82ca9d"
                        fill="#82ca9d"
                        name="Open Ports"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Grid>
            
            <Grid item xs={12} lg={4}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Top Services
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={serviceData}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {serviceData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Performance Metrics */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Performance Metrics
                  </Typography>
                  
                  <Box sx={{ mb: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                      <Typography variant="body2">Success Rate</Typography>
                      <Typography variant="body2">{stats.successRate}%</Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={stats.successRate}
                      color={stats.successRate > 80 ? 'success' : stats.successRate > 60 ? 'warning' : 'error'}
                      sx={{ height: 8, borderRadius: 4 }}
                    />
                  </Box>
                  
                  <Box sx={{ mb: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                      <Typography variant="body2">Port Discovery Rate</Typography>
                      <Typography variant="body2">
                        {stats.totalPorts > 0 ? Math.round((stats.openPorts / stats.totalPorts) * 100) : 0}%
                      </Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={stats.totalPorts > 0 ? (stats.openPorts / stats.totalPorts) * 100 : 0}
                      color="info"
                      sx={{ height: 8, borderRadius: 4 }}
                    />
                  </Box>
                  
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Average Scan Time: {formatDuration(stats.avgScanTime)}
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Quick Stats
                  </Typography>
                  
                  <List dense>
                    <ListItem>
                      <ListItemIcon>
                        <TrendingUp color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Most Active Day"
                        secondary={chartData.length > 0 
                          ? chartData.reduce((max, day) => day.scans > max.scans ? day : max, chartData[0]).date
                          : 'No data'
                        }
                      />
                    </ListItem>
                    
                    <ListItem>
                      <ListItemIcon>
                        <Security color="warning" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Most Common Service"
                        secondary={serviceData.length > 0 ? serviceData[0].name : 'No data'}
                      />
                    </ListItem>
                    
                    <ListItem>
                      <ListItemIcon>
                        <NetworkCheck color="info" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Total Ports Scanned"
                        secondary={stats.totalPorts.toLocaleString()}
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </>
      )}

      {/* Recent Scans */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Recent Scans
          </Typography>
          
          {scanHistory.length === 0 ? (
            <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 2 }}>
              No scans yet. Start your first scan to see it here.
            </Typography>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>Target</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Duration</TableCell>
                    <TableCell>Results</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {scanHistory.slice(0, 10).map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell>
                        <Typography variant="body2">
                          {new Date(scan.timestamp).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {scan.config?.targets || 'Unknown'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          icon={getStatusIcon(scan.status)}
                          label={scan.status}
                          color={getStatusColor(scan.status)}
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {scan.duration ? formatDuration(scan.duration) : '-'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {scan.stats?.openPorts || 0} open / {scan.stats?.totalPorts || 0} total
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={(e) => handleMenuOpen(e, scan)}
                        >
                          <MoreVert />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {/* Context Menu */}
      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={() => handleExportScan('json')}>
          <Download sx={{ mr: 1 }} />
          Export JSON
        </MenuItem>
        <MenuItem onClick={() => handleExportScan('csv')}>
          <Download sx={{ mr: 1 }} />
          Export CSV
        </MenuItem>
        <MenuItem onClick={() => handleExportScan('html')}>
          <Download sx={{ mr: 1 }} />
          Export HTML
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleDeleteScan} sx={{ color: 'error.main' }}>
          <Delete sx={{ mr: 1 }} />
          Delete Scan
        </MenuItem>
      </Menu>
    </Box>
  );
};

export default Dashboard;