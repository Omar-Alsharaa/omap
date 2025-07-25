import React, { createContext, useContext, useReducer, useEffect } from 'react';
import io from 'socket.io-client';

const ScanContext = createContext();

const initialState = {
  isScanning: false,
  currentScan: null,
  scanProgress: 0,
  scanResults: [],
  scanHistory: [],
  socket: null,
  error: null,
  scanStats: {
    totalHosts: 0,
    scannedHosts: 0,
    totalPorts: 0,
    scannedPorts: 0,
    openPorts: 0,
    startTime: null,
    estimatedTimeRemaining: null
  }
};

const scanReducer = (state, action) => {
  switch (action.type) {
    case 'START_SCAN':
      return {
        ...state,
        isScanning: true,
        currentScan: action.payload,
        scanProgress: 0,
        error: null,
        scanStats: {
          ...initialState.scanStats,
          startTime: new Date(),
          totalHosts: action.payload.targets?.length || 1,
          totalPorts: action.payload.ports?.length || 1000
        }
      };
    
    case 'UPDATE_PROGRESS':
      return {
        ...state,
        scanProgress: action.payload.progress,
        scanStats: {
          ...state.scanStats,
          ...action.payload.stats
        }
      };
    
    case 'ADD_RESULT':
      return {
        ...state,
        scanResults: [...state.scanResults, action.payload]
      };
    
    case 'COMPLETE_SCAN':
      return {
        ...state,
        isScanning: false,
        scanProgress: 100,
        scanHistory: [action.payload, ...state.scanHistory.slice(0, 9)]
      };
    
    case 'STOP_SCAN':
      return {
        ...state,
        isScanning: false,
        currentScan: null,
        scanProgress: 0
      };
    
    case 'SET_ERROR':
      return {
        ...state,
        error: action.payload,
        isScanning: false
      };
    
    case 'CLEAR_ERROR':
      return {
        ...state,
        error: null
      };
    
    case 'SET_SOCKET':
      return {
        ...state,
        socket: action.payload
      };
    
    case 'LOAD_HISTORY':
      return {
        ...state,
        scanHistory: action.payload
      };
    
    default:
      return state;
  }
};

export const ScanProvider = ({ children }) => {
  const [state, dispatch] = useReducer(scanReducer, initialState);

  useEffect(() => {
    // Initialize WebSocket connection
    const socket = io('http://localhost:8080', {
      transports: ['websocket', 'polling']
    });

    socket.on('connect', () => {
      console.log('Connected to OMAP server');
      dispatch({ type: 'SET_SOCKET', payload: socket });
    });

    socket.on('scan_progress', (data) => {
      dispatch({ type: 'UPDATE_PROGRESS', payload: data });
    });

    socket.on('scan_result', (data) => {
      dispatch({ type: 'ADD_RESULT', payload: data });
    });

    socket.on('scan_complete', (data) => {
      dispatch({ type: 'COMPLETE_SCAN', payload: data });
    });

    socket.on('scan_error', (error) => {
      dispatch({ type: 'SET_ERROR', payload: error.message });
    });

    socket.on('disconnect', () => {
      console.log('Disconnected from OMAP server');
    });

    // Load scan history from localStorage
    const savedHistory = localStorage.getItem('omapScanHistory');
    if (savedHistory) {
      dispatch({ type: 'LOAD_HISTORY', payload: JSON.parse(savedHistory) });
    }

    return () => {
      socket.disconnect();
    };
  }, []);

  // Save scan history to localStorage whenever it changes
  useEffect(() => {
    if (state.scanHistory.length > 0) {
      localStorage.setItem('omapScanHistory', JSON.stringify(state.scanHistory));
    }
  }, [state.scanHistory]);

  const startScan = async (scanConfig) => {
    try {
      dispatch({ type: 'START_SCAN', payload: scanConfig });
      
      if (state.socket) {
        state.socket.emit('start_scan', scanConfig);
      } else {
        throw new Error('WebSocket connection not available');
      }
    } catch (error) {
      dispatch({ type: 'SET_ERROR', payload: error.message });
    }
  };

  const stopScan = () => {
    if (state.socket) {
      state.socket.emit('stop_scan');
    }
    dispatch({ type: 'STOP_SCAN' });
  };

  const clearError = () => {
    dispatch({ type: 'CLEAR_ERROR' });
  };

  const exportResults = (format, scanId) => {
    const scan = state.scanHistory.find(s => s.id === scanId) || state.currentScan;
    if (!scan) return;

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `omap-scan-${timestamp}.${format}`;

    switch (format) {
      case 'json':
        const jsonData = JSON.stringify(scan, null, 2);
        downloadFile(jsonData, filename, 'application/json');
        break;
      
      case 'csv':
        const csvData = convertToCSV(scan.results);
        downloadFile(csvData, filename, 'text/csv');
        break;
      
      case 'html':
        const htmlData = generateHTMLReport(scan);
        downloadFile(htmlData, filename, 'text/html');
        break;
      
      default:
        console.error('Unsupported export format:', format);
    }
  };

  const downloadFile = (content, filename, mimeType) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const convertToCSV = (results) => {
    if (!results || results.length === 0) return '';
    
    const headers = ['Host', 'Port', 'State', 'Service', 'Version', 'Banner'];
    const rows = results.flatMap(host => 
      host.ports.map(port => [
        host.host,
        port.port,
        port.open ? 'open' : 'closed',
        port.service || '',
        port.version || '',
        port.banner || ''
      ])
    );
    
    return [headers, ...rows].map(row => 
      row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(',')
    ).join('\n');
  };

  const generateHTMLReport = (scan) => {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>OMAP Scan Report - ${scan.target}</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff41; }
        .header { border-bottom: 2px solid #00ff41; padding: 20px; }
        .results { padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #00ff41; padding: 8px; text-align: left; }
        th { background: #1a1a1a; }
        .open { color: #00ff41; }
        .closed { color: #ff6b35; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OMAP Scan Report</h1>
        <p>Target: ${scan.target}</p>
        <p>Scan Time: ${new Date(scan.timestamp).toLocaleString()}</p>
        <p>Duration: ${scan.duration}s</p>
    </div>
    <div class="results">
        <h2>Results Summary</h2>
        <p>Total Hosts: ${scan.results?.length || 0}</p>
        <p>Open Ports: ${scan.results?.reduce((acc, host) => acc + host.ports.filter(p => p.open).length, 0) || 0}</p>
        
        <h2>Detailed Results</h2>
        <table>
            <tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Banner</th></tr>
            ${scan.results?.flatMap(host => 
              host.ports.filter(p => p.open).map(port => 
                `<tr>
                    <td>${host.host}</td>
                    <td>${port.port}</td>
                    <td class="open">open</td>
                    <td>${port.service || 'unknown'}</td>
                    <td>${port.version || '-'}</td>
                    <td>${port.banner || '-'}</td>
                </tr>`
              )
            ).join('') || '<tr><td colspan="6">No open ports found</td></tr>'}
        </table>
    </div>
</body>
</html>`;
  };

  const value = {
    ...state,
    startScan,
    stopScan,
    clearError,
    exportResults
  };

  return (
    <ScanContext.Provider value={value}>
      {children}
    </ScanContext.Provider>
  );
};

export const useScan = () => {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
};

export default ScanContext;