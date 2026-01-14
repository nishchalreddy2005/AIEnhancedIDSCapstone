import React, { useState, useEffect } from 'react';
import { Upload, FileText, AlertTriangle, CheckCircle, XCircle, Eye, Activity, Pause } from 'lucide-react';

interface IntrusionResult {
  status: 'safe' | 'warning' | 'danger';
  confidence: number;
  details: string;
  timestamp: string;
}

export default function CheckIntrusion() {
  // const [activeTab, setActiveTab] = useState<'manual' | 'upload'>('manual');
  const [activeTab, setActiveTab] = useState<'manual' | 'upload' | 'live'>('manual');

  const [logInput, setLogInput] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [result, setResult] = useState<IntrusionResult | null>(null);
  const [loading, setLoading] = useState(false);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file && file.type === 'text/csv') {
      setSelectedFile(file);
    } else {
      alert('Please select a valid CSV file');
    }
  };

  const analyzeManualLog = async () => {
    if (!logInput.trim()) {
      alert('Please enter log data');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/analyze-logs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ log_data: logInput })
      });

      if (!response.ok) {
        throw new Error('Analysis failed');
      }

      const result = await response.json();
      setResult({
        status: result.status,
        confidence: result.confidence,
        details: result.details,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Analysis failed:', error);
      console.log('Error:', error);
      alert('Failed to analyze logs. Please make sure the backend server is running.');
    } finally {
      setLoading(false);
    }
  };

  const analyzeFileUpload = async () => {
    if (!selectedFile) {
      alert('Please select a CSV file');
      return;
    }

    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await fetch('http://localhost:5000/analyze-csv', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error('File analysis failed');
      }

      const result = await response.json();
      setResult({
        status: result.status,
        confidence: result.confidence,
        details: result.details,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('File analysis failed:', error);
      alert('Failed to analyze CSV file. Please make sure the backend server is running.');
    } finally {
      setLoading(false);
    }
  };



  /* =========================
     LIVE MONITORING LOGIC
  ========================= */
  const [liveRunning, setLiveRunning] = useState(false);

  useEffect(() => {
    if (!liveRunning) return;

    const interval = setInterval(async () => {
      try {
        const response = await fetch('http://localhost:5000/analyse-live');
        if (!response.ok) return;

        const data = await response.json();
        setResult({
          status: data.status,
          confidence: data.confidence,
          details: data.details,
          timestamp: new Date().toISOString()
        });
      } catch (err) {
        console.error('Live monitoring error:', err);
      }
    }, 5000); // poll every 5 seconds

    return () => clearInterval(interval);
  }, [liveRunning]);



  const getResultIcon = (status: string) => {
    switch (status) {
      case 'safe':
        return <CheckCircle className="h-8 w-8 text-green-400" />;
      case 'warning':
        return <AlertTriangle className="h-8 w-8 text-yellow-400" />;
      case 'danger':
        return <XCircle className="h-8 w-8 text-red-400" />;
      default:
        return null;
    }
  };

  const getResultColor = (status: string) => {
    switch (status) {
      case 'safe':
        return 'from-green-600/20 to-green-800/20 border-green-500/30';
      case 'warning':
        return 'from-yellow-600/20 to-yellow-800/20 border-yellow-500/30';
      case 'danger':
        return 'from-red-600/20 to-red-800/20 border-red-500/30';
      default:
        return '';
    }
  };

  return (
    <div className="min-h-screen px-4 sm:px-6 lg:px-8 py-12">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-12">
          <div className="flex justify-center mb-6">
            <div className="p-4 bg-red-600/20 backdrop-blur-sm rounded-2xl border border-red-500/30">
              <AlertTriangle className="h-12 w-12 text-red-400" />
            </div>
          </div>
          <h1 className="text-4xl font-bold text-white mb-4">Network Intrusion Detection</h1>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            Analyze your network logs using our advanced AI model to detect potential security threats
          </p>
        </div>

        <div className="bg-slate-800/40 backdrop-blur-sm rounded-2xl border border-slate-700/50 p-8">
          {/* Tab Navigation */}
          <div className="flex mb-8 bg-slate-700/30 rounded-xl p-1">
            <button
              onClick={() => setActiveTab('manual')}
              className={`flex-1 py-3 px-6 rounded-lg font-medium transition-all ${activeTab === 'manual'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'text-gray-400 hover:text-white'
                }`}
            >
              <FileText className="h-5 w-5 inline mr-2" />
              Manual Input
            </button>
            <button
              onClick={() => setActiveTab('upload')}
              className={`flex-1 py-3 px-6 rounded-lg font-medium transition-all ${activeTab === 'upload'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'text-gray-400 hover:text-white'
                }`}
            >
              <Upload className="h-5 w-5 inline mr-2" />
              CSV Upload
            </button>
            <button
              onClick={() => setActiveTab('live')}
              className={`flex-1 py-3 px-6 rounded-lg font-medium transition-all ${activeTab === 'live'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-gray-400 hover:text-white'
                }`}
            >
              <Activity className="h-5 w-5 inline mr-2" />
              Live Monitoring
            </button>
          </div>

          {/* Manual Input Tab */}
          {activeTab === 'manual' && (
            <div className="space-y-6">
              <div>
                <label className="block text-lg font-medium text-white mb-3">
                  Enter Log Data
                </label>
                <textarea
                  value={logInput}
                  onChange={(e) => setLogInput(e.target.value)}
                  placeholder="Paste your network logs here..."
                  rows={10}
                  className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white placeholder-gray-400 font-mono"
                />
              </div>
              <button
                onClick={analyzeManualLog}
                disabled={loading}
                className="w-full py-4 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold rounded-lg transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Analyzing...' : 'Analyze Logs'}
              </button>
            </div>
          )}

          {/* File Upload Tab */}
          {activeTab === 'upload' && (
            <div className="space-y-6">
              <div className="border-2 border-dashed border-slate-600 rounded-xl p-8 text-center hover:border-slate-500 transition-colors">
                <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-lg text-white mb-2">Upload CSV File</p>
                <p className="text-gray-400 mb-6">
                  Only CSV files with specified headers are accepted
                </p>
                <input
                  type="file"
                  accept=".csv"
                  onChange={handleFileSelect}
                  className="hidden"
                  id="csv-upload"
                />
                <label
                  htmlFor="csv-upload"
                  className="inline-flex items-center px-6 py-3 bg-slate-700/50 hover:bg-slate-700 text-white font-medium rounded-lg border border-slate-600 cursor-pointer transition-colors"
                >
                  Choose File
                </label>
                {selectedFile && (
                  <p className="mt-4 text-green-400">Selected: {selectedFile.name}</p>
                )}
              </div>
              <div className="bg-slate-700/30 rounded-lg p-4">
                <h4 className="text-white font-medium mb-2">Required CSV Headers:</h4>
                {/* <code className="text-sm text-cyan-400">
                  timestamp, source_ip, dest_ip, port, protocol, packet_size, flags
                </code> */}
                <code className="text-sm text-cyan-400" style={{ whiteSpace: 'pre-line' }}>
                  duration  protocol_type  service  flag  src_bytes  dst_bytes  land  wrong_fragment  urgent  hot  num_failed_logins
                  logged_in  lnum_compromised  lroot_shell  lsu_attempted  lnum_root  lnum_file_creations  lnum_shells  lnum_access_files  lnum_outbound_cmds  is_host_login
                  is_guest_login  count  srv_count  serror_rate  srv_serror_rate  rerror_rate  srv_rerror_rate  same_srv_rate  diff_srv_rate
                  srv_diff_host_rate  dst_host_count  dst_host_srv_count  dst_host_same_srv_rate  dst_host_diff_srv_rate  dst_host_same_src_port_rate  dst_host_srv_diff_host_rate
                  dst_host_serror_rate  dst_host_srv_serror_rate  dst_host_rerror_rate  dst_host_srv_rerror_rate  label
                </code>

              </div>
              <button
                onClick={analyzeFileUpload}
                disabled={loading || !selectedFile}
                className="w-full py-4 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold rounded-lg transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Processing...' : 'Analyze File'}
              </button>
            </div>
          )}

          {/* Live */}
          {activeTab === 'live' && (
            <div className="space-y-6 text-center">
              <p className="text-gray-300">
                Real-time AI-based network intrusion monitoring
              </p>

              <button
                onClick={() => setLiveRunning(!liveRunning)}
                className={`w-full py-4 rounded-lg font-semibold ${liveRunning
                  ? 'bg-red-600 hover:bg-red-700'
                  : 'bg-green-600 hover:bg-green-700'
                  }`}
              >
                {liveRunning ? (
                  <>
                    <Pause className="inline mr-2 h-5 w-5" />
                    Stop Monitoring
                  </>
                ) : (
                  <>
                    <Activity className="inline mr-2 h-5 w-5" />
                    Start Live Monitoring
                  </>
                )}
              </button>
            </div>
          )}

          {/* Results */}
          {result && (
            <div className="mt-8 pt-8 border-t border-slate-700">
              <h3 className="text-xl font-semibold text-white mb-6 flex items-center">
                <Eye className="h-6 w-6 mr-2" />
                Analysis Results
              </h3>
              <div className={`bg-gradient-to-r ${getResultColor(result.status)} rounded-xl p-6 border`}>
                <div className="flex items-start space-x-4">
                  {getResultIcon(result.status)}
                  <div className="flex-1">
                    <h4 className="text-xl font-semibold text-white mb-2">
                      {result.status === 'safe' && 'No Threats Detected'}
                      {result.status === 'warning' && 'Potential Threat Detected'}
                      {result.status === 'danger' && 'Critical Threat Detected'}
                    </h4>
                    <p className="text-gray-300 mb-4">{result.details}</p>
                    <div className="flex items-center space-x-6 text-sm">
                      <span className="text-gray-400">
                        Confidence: <span className="font-semibold text-white">{result.confidence}%</span>
                      </span>
                      <span className="text-gray-400">
                        Analyzed: <span className="font-semibold text-white">
                          {new Date(result.timestamp).toLocaleString()}
                        </span>
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// export default CheckIntrusion