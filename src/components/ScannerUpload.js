import React, { useState, useRef } from 'react';
import { Upload, FileText, X, AlertCircle, CheckCircle } from 'lucide-react';
import { parseUniversalScanner, detectScannerType } from '../utils/scannerParsers';

const ScannerUpload = ({ onFileUpload, onError, loading, setLoading }) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileType, setFileType] = useState('auto');
  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  const handleFile = async (file) => {
    setSelectedFile(file);
    setLoading(true);
    
    try {
      const parsedData = await parseFile(file, fileType);
      onFileUpload(parsedData);
    } catch (error) {
      onError(`Failed to parse file: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const parseFile = async (file, type) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (e) => {
        try {
          const content = e.target.result;
          let parsedContent;
          let detectedFileType = type;
          
          // Auto-detect file type if not specified
          if (type === 'auto') {
            if (file.name.endsWith('.json')) {
              detectedFileType = 'json';
            } else if (file.name.endsWith('.xml') || file.name.endsWith('.nessus')) {
              detectedFileType = 'xml';
            } else if (file.name.endsWith('.csv')) {
              detectedFileType = 'csv';
            } else {
              // Try to detect based on content
              try {
                JSON.parse(content);
                detectedFileType = 'json';
              } catch {
                if (content.includes('<?xml') || content.includes('<')) {
                  detectedFileType = 'xml';
                } else if (content.includes(',')) {
                  detectedFileType = 'csv';
                } else {
                  detectedFileType = 'unknown';
                }
              }
            }
          }
          
          // Parse content based on detected type
          if (detectedFileType === 'json') {
            parsedContent = JSON.parse(content);
          } else if (detectedFileType === 'xml') {
            // For XML, we'll pass the raw string to the parser
            parsedContent = content;
          } else if (detectedFileType === 'csv') {
            parsedContent = content;
          } else {
            parsedContent = content;
          }
          
          // Detect scanner type and parse accordingly
          const scannerType = detectScannerType(parsedContent, file.name);
          console.log(`Detected scanner type: ${scannerType} for file: ${file.name}`);
          
          // Use the universal parser
          const vulnerabilities = parseUniversalScanner(parsedContent, file.name, detectedFileType);
          
          // Apply additional processing
          const processedVulns = vulnerabilities.map(vuln => ({
            ...vuln,
            riskScore: calculateRiskScore(vuln),
            severity: mapSeverity(vuln.severity)
          }));
          
          console.log('Parsed vulnerabilities:', processedVulns.length);
          console.log('Sample vulnerability:', processedVulns[0]);
          console.log('Severity distribution:', processedVulns.reduce((acc, v) => {
            acc[v.severity] = (acc[v.severity] || 0) + 1;
            return acc;
          }, {}));
          
          resolve(processedVulns);
          
        } catch (error) {
          console.error('Parse error:', error);
          reject(new Error(`Failed to parse ${file.name}: ${error.message}`));
        }
      };
      
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsText(file);
    });
  };

  const parseJSONData = (data) => {
    // Handle different JSON formats from various scanners
    let vulnerabilities = [];
    
    // Nessus format (.nessus JSON export)
    if (data.vulnerabilities) {
      vulnerabilities = data.vulnerabilities.map(vuln => ({
        cveId: vuln.cve || vuln.cve_id || vuln.plugin_id || 'N/A',
        title: vuln.name || vuln.title || vuln.plugin_name || 'Unknown Vulnerability',
        description: vuln.description || vuln.synopsis || vuln.plugin_output || 'No description available',
        severity: mapSeverity(vuln.severity || vuln.risk || vuln.risk_factor || 'Unknown'),
        riskScore: calculateRiskScore(vuln),
        asset: vuln.host || vuln.asset || vuln.hostname || 'Unknown',
        exploitAvailable: vuln.exploit_available || vuln.exploitAvailable || vuln.exploitable || false,
        publishedDate: vuln.published || vuln.plugin_publication_date || new Date().toISOString(),
        cvssScore: vuln.cvss_score || vuln.cvssScore || vuln.cvss_base_score || 'N/A',
        port: vuln.port || 'N/A',
        protocol: vuln.protocol || 'N/A'
      }));
    }
    // OpenVAS format
    else if (data.results) {
      vulnerabilities = data.results.map(vuln => ({
        cveId: vuln.cve || vuln.cve_id || vuln.nvt?.oid || 'N/A',
        title: vuln.name || vuln.title || vuln.nvt?.name || 'Unknown Vulnerability',
        description: vuln.description || vuln.summary || vuln.nvt?.summary || 'No description available',
        severity: mapSeverity(vuln.severity || vuln.threat || 'Unknown'),
        riskScore: calculateRiskScore(vuln),
        asset: vuln.host || vuln.asset || vuln.target || 'Unknown',
        exploitAvailable: vuln.exploit_available || false,
        publishedDate: vuln.published || vuln.creation_time || new Date().toISOString(),
        cvssScore: vuln.cvss_score || vuln.severity || 'N/A',
        port: vuln.port || 'N/A'
      }));
    }
    // Qualys format
    else if (data.SCAN && data.SCAN.IP) {
      vulnerabilities = [];
      const ips = Array.isArray(data.SCAN.IP) ? data.SCAN.IP : [data.SCAN.IP];
      ips.forEach(ip => {
        const vulns = Array.isArray(ip.VULN) ? ip.VULN : [ip.VULN];
        vulns.forEach(vuln => {
          vulnerabilities.push({
            cveId: vuln.CVE_ID || vuln.QID || 'N/A',
            title: vuln.TITLE || 'Unknown Vulnerability',
            description: vuln.DIAGNOSIS || vuln.CONSEQUENCE || 'No description available',
            severity: mapSeverity(vuln.SEVERITY || 'Unknown'),
            riskScore: calculateRiskScore(vuln),
            asset: ip.value || ip.IP || 'Unknown',
            exploitAvailable: vuln.EXPLOITABILITY === 'Exploitable' || false,
            publishedDate: vuln.FIRST_FOUND || new Date().toISOString(),
            cvssScore: vuln.CVSS_SCORE || vuln.CVSS_BASE || 'N/A',
            port: vuln.PORT || 'N/A'
          });
        });
      });
    }
    // Rapid7/Nexpose format
    else if (data.scan && data.scan.nodes) {
      vulnerabilities = [];
      data.scan.nodes.forEach(node => {
        if (node.vulnerabilities) {
          node.vulnerabilities.forEach(vuln => {
            vulnerabilities.push({
              cveId: vuln.id || vuln.cve || 'N/A',
              title: vuln.title || vuln.name || 'Unknown Vulnerability',
              description: vuln.description || vuln.summary || 'No description available',
              severity: mapSeverity(vuln.severity || vuln.riskScore || 'Unknown'),
              riskScore: calculateRiskScore(vuln),
              asset: node.address || node.name || 'Unknown',
              exploitAvailable: vuln.malwareKits > 0 || vuln.exploits > 0 || false,
              publishedDate: vuln.published || new Date().toISOString(),
              cvssScore: vuln.cvssScore || 'N/A',
              port: vuln.port || 'N/A'
            });
          });
        }
      });
    }
    // Nmap Vulners script output
    else if (data.nmaprun && data.nmaprun.host) {
      vulnerabilities = [];
      const hosts = Array.isArray(data.nmaprun.host) ? data.nmaprun.host : [data.nmaprun.host];
      hosts.forEach(host => {
        if (host.ports && host.ports.port) {
          const ports = Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port];
          ports.forEach(port => {
            if (port.script) {
              const scripts = Array.isArray(port.script) ? port.script : [port.script];
              scripts.forEach(script => {
                if (script.id === 'vulners' && script.output) {
                  const cveMatches = script.output.match(/CVE-\d{4}-\d{4,}/g) || [];
                  cveMatches.forEach(cve => {
                    vulnerabilities.push({
                      cveId: cve,
                      title: `Vulnerability found on port ${port.portid}`,
                      description: script.output,
                      severity: 'Unknown',
                      riskScore: calculateRiskScore({}),
                      asset: host.address?.addr || 'Unknown',
                      exploitAvailable: false,
                      publishedDate: new Date().toISOString(),
                      cvssScore: 'N/A',
                      port: port.portid,
                      protocol: port.protocol
                    });
                  });
                }
              });
            }
          });
        }
      });
    }
    // Generic format
    else if (Array.isArray(data)) {
      vulnerabilities = data.map(vuln => ({
        cveId: vuln.cveId || vuln.cve_id || vuln.cve || vuln.id || 'N/A',
        title: vuln.title || vuln.name || vuln.summary || 'Unknown Vulnerability',
        description: vuln.description || vuln.details || vuln.synopsis || 'No description available',
        severity: mapSeverity(vuln.severity || vuln.risk || vuln.threat || 'Unknown'),
        riskScore: calculateRiskScore(vuln),
        asset: vuln.asset || vuln.host || vuln.hostname || vuln.target || 'Unknown',
        exploitAvailable: vuln.exploitAvailable || vuln.exploit_available || vuln.exploitable || false,
        publishedDate: vuln.publishedDate || vuln.published || vuln.date || new Date().toISOString(),
        cvssScore: vuln.cvssScore || vuln.cvss_score || vuln.cvss || 'N/A',
        port: vuln.port || 'N/A',
        protocol: vuln.protocol || 'N/A'
      }));
    }
    // Single vulnerability object
    else if (data.cve || data.cveId || data.id) {
      vulnerabilities = [{
        cveId: data.cveId || data.cve_id || data.cve || data.id || 'N/A',
        title: data.title || data.name || data.summary || 'Unknown Vulnerability',
        description: data.description || data.details || data.synopsis || 'No description available',
        severity: mapSeverity(data.severity || data.risk || data.threat || 'Unknown'),
        riskScore: calculateRiskScore(data),
        asset: data.asset || data.host || data.hostname || data.target || 'Unknown',
        exploitAvailable: data.exploitAvailable || data.exploit_available || data.exploitable || false,
        publishedDate: data.publishedDate || data.published || data.date || new Date().toISOString(),
        cvssScore: data.cvssScore || data.cvss_score || data.cvss || 'N/A',
        port: data.port || 'N/A',
        protocol: data.protocol || 'N/A'
      }];
    }
    
    if (vulnerabilities.length === 0) {
      throw new Error('No vulnerability data found in the file. Please check the file format and ensure it contains vulnerability information.');
    }
    
    return vulnerabilities;
  };

  const parseXMLData = (xmlDoc) => {
    // Simple XML parsing for common scanner formats
    const vulnerabilities = [];
    const vulnNodes = xmlDoc.querySelectorAll('vulnerability, finding, result');
    
    vulnNodes.forEach(node => {
      const vuln = {
        cveId: getXMLText(node, 'cve, cve_id, cve-id') || 'N/A',
        title: getXMLText(node, 'name, title, summary') || 'Unknown Vulnerability',
        description: getXMLText(node, 'description, synopsis, details') || 'No description available',
        severity: mapSeverity(getXMLText(node, 'severity, risk, threat') || 'Unknown'),
        riskScore: calculateRiskScore({ severity: getXMLText(node, 'severity, risk, threat') }),
        asset: getXMLText(node, 'host, asset, target') || 'Unknown',
        exploitAvailable: getXMLText(node, 'exploit_available, exploitAvailable') === 'true',
        publishedDate: getXMLText(node, 'published, date') || new Date().toISOString(),
        cvssScore: getXMLText(node, 'cvss_score, cvssScore') || 'N/A'
      };
      vulnerabilities.push(vuln);
    });
    
    if (vulnerabilities.length === 0) {
      throw new Error('No vulnerability data found in the XML file.');
    }
    
    return vulnerabilities;
  };

  const parseCSVData = (csvText) => {
    const lines = csvText.split('\n');
    const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
    const vulnerabilities = [];
    
    for (let i = 1; i < lines.length; i++) {
      if (lines[i].trim()) {
        const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
        const vuln = {};
        
        headers.forEach((header, index) => {
          vuln[header.toLowerCase()] = values[index] || '';
        });
        
        vulnerabilities.push({
          cveId: vuln.cve || vuln.cve_id || vuln.cveid || 'N/A',
          title: vuln.title || vuln.name || vuln.summary || 'Unknown Vulnerability',
          description: vuln.description || vuln.details || 'No description available',
          severity: mapSeverity(vuln.severity || vuln.risk || vuln.threat || 'Unknown'),
          riskScore: calculateRiskScore({ severity: vuln.severity || vuln.risk || vuln.threat }),
          asset: vuln.asset || vuln.host || vuln.target || 'Unknown',
          exploitAvailable: vuln.exploit_available === 'true' || vuln.exploitavailable === 'true',
          publishedDate: vuln.published || vuln.date || new Date().toISOString(),
          cvssScore: vuln.cvss_score || vuln.cvssscore || 'N/A'
        });
      }
    }
    
    if (vulnerabilities.length === 0) {
      throw new Error('No vulnerability data found in the CSV file.');
    }
    
    return vulnerabilities;
  };

  const getXMLText = (node, selectors) => {
    const selectorList = selectors.split(', ');
    for (const selector of selectorList) {
      const element = node.querySelector(selector);
      if (element && element.textContent) {
        return element.textContent.trim();
      }
    }
    return '';
  };

  const mapSeverity = (severity) => {
    if (!severity) return 'Unknown';
    
    const sev = severity.toString().toLowerCase();
    if (sev.includes('critical') || sev.includes('crit')) return 'Critical';
    if (sev.includes('high') || sev.includes('high')) return 'High';
    if (sev.includes('medium') || sev.includes('med')) return 'Medium';
    if (sev.includes('low') || sev.includes('low')) return 'Low';
    if (sev.includes('info') || sev.includes('informational')) return 'Info';
    
    return 'Unknown';
  };

  const calculateRiskScore = (vuln) => {
    // Basic risk score calculation based on severity
    const severity = vuln.severity || 'Unknown';
    const baseScore = {
      'Critical': 100,
      'High': 75,
      'Medium': 50,
      'Low': 25,
      'Info': 10,
      'Unknown': 30
    };
    
    let score = baseScore[severity] || 30;
    
    // Add bonus for exploit availability
    if (vuln.exploitAvailable || vuln.exploit_available) {
      score += 20;
    }
    
    // Add bonus for CVSS score if available
    if (vuln.cvssScore && vuln.cvssScore !== 'N/A') {
      const cvss = parseFloat(vuln.cvssScore);
      if (!isNaN(cvss)) {
        if (cvss >= 9.0) score += 15;
        else if (cvss >= 7.0) score += 10;
        else if (cvss >= 4.0) score += 5;
      }
    }
    
    return Math.min(score, 100);
  };

  const removeFile = () => {
    setSelectedFile(null);
    onError(null);
  };

  const openFileDialog = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      <div className="text-center">
        <Upload className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-sm font-medium text-gray-900">Upload Scanner Output</h3>
        <p className="mt-1 text-sm text-gray-500">
          Upload JSON, XML, or CSV files from your vulnerability scanner
        </p>
      </div>

      {/* File Type Selection */}
      <div className="mt-4">
        <label className="block text-sm font-medium text-gray-700 mb-2">
          File Type (Optional - Auto-detected)
        </label>
        <select
          value={fileType}
          onChange={(e) => setFileType(e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
        >
          <option value="auto">Auto-detect</option>
          <option value="json">JSON</option>
          <option value="xml">XML</option>
          <option value="csv">CSV</option>
        </select>
      </div>

      {/* Drag & Drop Area */}
      <div
        className={`mt-4 relative border-2 border-dashed rounded-lg p-6 text-center ${
          dragActive
            ? 'border-primary-400 bg-primary-50'
            : 'border-gray-300 hover:border-gray-400'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          accept=".json,.xml,.csv"
          onChange={handleFileInput}
        />
        
        {!selectedFile ? (
          <div>
            <FileText className="mx-auto h-8 w-8 text-gray-400" />
            <p className="mt-2 text-sm text-gray-600">
              <button
                type="button"
                onClick={openFileDialog}
                className="font-medium text-primary-600 hover:text-primary-500"
              >
                Click to upload
              </button>
              {' '}or drag and drop
            </p>
            <p className="mt-1 text-xs text-gray-500">
              JSON, XML, or CSV files up to 10MB
            </p>
          </div>
        ) : (
          <div className="flex items-center justify-center">
            <CheckCircle className="h-8 w-8 text-green-500 mr-3" />
            <div className="text-left">
              <p className="text-sm font-medium text-gray-900">{selectedFile.name}</p>
              <p className="text-xs text-gray-500">
                {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
              </p>
            </div>
            <button
              onClick={removeFile}
              className="ml-4 p-1 text-gray-400 hover:text-gray-600"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        )}
      </div>

      {/* Loading State */}
      {loading && (
        <div className="mt-4 flex items-center justify-center">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary-600"></div>
          <span className="ml-2 text-sm text-gray-600">Processing file...</span>
        </div>
      )}

      {/* Supported Formats Info */}
      <div className="mt-6 bg-gray-50 rounded-lg p-4">
        <h4 className="text-sm font-medium text-gray-700 mb-3">Supported Vulnerability Scanners</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-xs text-gray-600">
          <div className="flex items-center">
            <CheckCircle className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
            <span>Nessus (.nessus, .json, .csv)</span>
          </div>
          <div className="flex items-center">
            <CheckCircle className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
            <span>OpenVAS (.xml, .json)</span>
          </div>
          <div className="flex items-center">
            <CheckCircle className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
            <span>Qualys VMDR (.xml, .json)</span>
          </div>
          <div className="flex items-center">
            <CheckCircle className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
            <span>Rapid7 Nexpose (.xml, .json)</span>
          </div>
          <div className="flex items-center">
            <CheckCircle className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
            <span>Nmap Vulners (.xml)</span>
          </div>
          <div className="flex items-center">
            <CheckCircle className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
            <span>Nikto (.csv, .xml)</span>
          </div>
          <div className="flex items-center">
            <CheckCircle className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
            <span>Burp Suite (.xml, .json)</span>
          </div>
          <div className="flex items-center">
            <CheckCircle className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
            <span>OWASP ZAP (.xml, .json)</span>
          </div>
          <div className="flex items-center">
            <CheckCircle className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
            <span>Acunetix (.xml, .json)</span>
          </div>
          <div className="flex items-center">
            <CheckCircle className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
            <span>Generic formats (JSON, XML, CSV)</span>
          </div>
        </div>
        
        <div className="mt-4 p-3 bg-blue-50 rounded-lg border border-blue-200">
          <div className="flex items-start">
            <AlertCircle className="h-4 w-4 text-blue-600 mr-2 mt-0.5 flex-shrink-0" />
            <div className="text-xs text-blue-800">
              <strong>Pro Tip:</strong> Simply export your scanner results in their native format and upload directly. 
              Our intelligent parser will automatically detect the scanner type and extract vulnerability data with 
              contextual risk analysis and prioritized remediation advice.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScannerUpload;
