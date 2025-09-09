import React, { useState } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  IconButton,
  Menu,
  MenuItem,
  Box,
  Badge,
  Tooltip,
  Divider,
  ListItemIcon,
  ListItemText,
  Switch,
  FormControlLabel
} from '@mui/material';
import {
  Dashboard,
  Search,
  Assessment,
  History,
  Settings,
  Help,
  Brightness4,
  Brightness7,
  Download,
  Info,
  GitHub,
  BugReport
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { useScan } from '../context/ScanContext';

const Navigation = ({ darkMode, onToggleDarkMode }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { isScanning, scanHistory, exportResults } = useScan();
  const [settingsAnchor, setSettingsAnchor] = useState(null);
  const [helpAnchor, setHelpAnchor] = useState(null);
  const [notifications, setNotifications] = useState(true);

  const navigationItems = [
    {
      label: 'Dashboard',
      path: '/',
      icon: <Dashboard />
    },
    {
      label: 'New Scan',
      path: '/scan',
      icon: <Search />
    },
    {
      label: 'Results',
      path: '/results',
      icon: <Assessment />
    },
    {
      label: 'History',
      path: '/history',
      icon: <History />
    }
  ];

  const handleSettingsOpen = (event) => {
    setSettingsAnchor(event.currentTarget);
  };

  const handleSettingsClose = () => {
    setSettingsAnchor(null);
  };

  const handleHelpOpen = (event) => {
    setHelpAnchor(event.currentTarget);
  };

  const handleHelpClose = () => {
    setHelpAnchor(null);
  };

  const handleExportAll = (format) => {
    const allResults = scanHistory
      .filter(scan => scan.results && scan.results.length > 0)
      .flatMap(scan => scan.results);
    
    if (allResults.length > 0) {
      exportResults(format, allResults);
    }
    handleSettingsClose();
  };

  const getActiveStyle = (path) => {
    const isActive = location.pathname === path;
    return {
      color: isActive ? 'primary.main' : 'inherit',
      backgroundColor: isActive ? 'action.selected' : 'transparent',
      '&:hover': {
        backgroundColor: 'action.hover'
      }
    };
  };

  return (
    <AppBar position="static" elevation={1}>
      <Toolbar>
        {/* Logo and Title */}
        <Box sx={{ display: 'flex', alignItems: 'center', mr: 4 }}>
          <Search sx={{ mr: 1, fontSize: 28 }} />
          <Typography variant="h6" component="div" sx={{ fontWeight: 'bold' }}>
            OMAP
          </Typography>
          <Typography variant="caption" sx={{ ml: 1, opacity: 0.7 }}>
            v2.0
          </Typography>
        </Box>

        {/* Navigation Items */}
        <Box sx={{ flexGrow: 1, display: 'flex', gap: 1 }}>
          {navigationItems.map((item) => (
            <Button
              key={item.path}
              startIcon={item.icon}
              onClick={() => navigate(item.path)}
              sx={getActiveStyle(item.path)}
            >
              {item.label}
            </Button>
          ))}
        </Box>

        {/* Status Indicator */}
        {isScanning && (
          <Box sx={{ mr: 2 }}>
            <Badge color="secondary" variant="dot">
              <Tooltip title="Scan in progress">
                <Search sx={{ animation: 'pulse 2s infinite' }} />
              </Tooltip>
            </Badge>
          </Box>
        )}

        {/* Scan History Badge */}
        <Box sx={{ mr: 2 }}>
          <Badge badgeContent={scanHistory.length} color="primary" max={99}>
            <Tooltip title={`${scanHistory.length} scans in history`}>
              <History />
            </Tooltip>
          </Badge>
        </Box>

        {/* Dark Mode Toggle */}
        <Tooltip title={`Switch to ${darkMode ? 'light' : 'dark'} mode`}>
          <IconButton
            onClick={onToggleDarkMode}
            color="inherit"
            sx={{ mr: 1 }}
          >
            {darkMode ? <Brightness7 /> : <Brightness4 />}
          </IconButton>
        </Tooltip>

        {/* Settings Menu */}
        <Tooltip title="Settings">
          <IconButton
            onClick={handleSettingsOpen}
            color="inherit"
            sx={{ mr: 1 }}
          >
            <Settings />
          </IconButton>
        </Tooltip>

        {/* Help Menu */}
        <Tooltip title="Help">
          <IconButton
            onClick={handleHelpOpen}
            color="inherit"
          >
            <Help />
          </IconButton>
        </Tooltip>

        {/* Settings Menu */}
        <Menu
          anchorEl={settingsAnchor}
          open={Boolean(settingsAnchor)}
          onClose={handleSettingsClose}
          PaperProps={{
            sx: { minWidth: 250 }
          }}
        >
          <MenuItem>
            <FormControlLabel
              control={
                <Switch
                  checked={notifications}
                  onChange={(e) => setNotifications(e.target.checked)}
                  size="small"
                />
              }
              label="Notifications"
              sx={{ width: '100%', m: 0 }}
            />
          </MenuItem>
          
          <MenuItem>
            <FormControlLabel
              control={
                <Switch
                  checked={darkMode}
                  onChange={onToggleDarkMode}
                  size="small"
                />
              }
              label="Dark Mode"
              sx={{ width: '100%', m: 0 }}
            />
          </MenuItem>
          
          <Divider />
          
          <MenuItem onClick={() => handleExportAll('json')}>
            <ListItemIcon>
              <Download />
            </ListItemIcon>
            <ListItemText primary="Export All (JSON)" />
          </MenuItem>
          
          <MenuItem onClick={() => handleExportAll('csv')}>
            <ListItemIcon>
              <Download />
            </ListItemIcon>
            <ListItemText primary="Export All (CSV)" />
          </MenuItem>
          
          <MenuItem onClick={() => handleExportAll('html')}>
            <ListItemIcon>
              <Download />
            </ListItemIcon>
            <ListItemText primary="Export All (HTML)" />
          </MenuItem>
          
          <Divider />
          
          <MenuItem onClick={() => {
            localStorage.clear();
            window.location.reload();
          }}>
            <ListItemIcon>
              <Settings />
            </ListItemIcon>
            <ListItemText primary="Reset Settings" />
          </MenuItem>
        </Menu>

        {/* Help Menu */}
        <Menu
          anchorEl={helpAnchor}
          open={Boolean(helpAnchor)}
          onClose={handleHelpClose}
          PaperProps={{
            sx: { minWidth: 200 }
          }}
        >
          <MenuItem onClick={() => {
            window.open('https://github.com/yourusername/omap', '_blank');
            handleHelpClose();
          }}>
            <ListItemIcon>
              <GitHub />
            </ListItemIcon>
            <ListItemText primary="GitHub Repository" />
          </MenuItem>
          
          <MenuItem onClick={() => {
            window.open('https://github.com/yourusername/omap/wiki', '_blank');
            handleHelpClose();
          }}>
            <ListItemIcon>
              <Help />
            </ListItemIcon>
            <ListItemText primary="Documentation" />
          </MenuItem>
          
          <MenuItem onClick={() => {
            window.open('https://github.com/yourusername/omap/issues', '_blank');
            handleHelpClose();
          }}>
            <ListItemIcon>
              <BugReport />
            </ListItemIcon>
            <ListItemText primary="Report Issue" />
          </MenuItem>
          
          <Divider />
          
          <MenuItem onClick={() => {
            // Show about dialog or navigate to about page
            handleHelpClose();
          }}>
            <ListItemIcon>
              <Info />
            </ListItemIcon>
            <ListItemText primary="About OMAP" />
          </MenuItem>
        </Menu>
      </Toolbar>
      
      {/* Add pulse animation for scanning indicator */}
      <style>
        {`
          @keyframes pulse {
            0% {
              opacity: 1;
            }
            50% {
              opacity: 0.5;
            }
            100% {
              opacity: 1;
            }
          }
        `}
      </style>
    </AppBar>
  );
};

export default Navigation;