// Enhanced scanner parsers for various vulnerability scanner formats

export const detectScannerType = (content, filename) => {
  const lowerFilename = filename.toLowerCase();
  const contentStr = typeof content === 'string' ? content : JSON.stringify(content);
  
  // Nessus detection
  if (lowerFilename.includes('nessus') || contentStr.includes('NessusClientData') || contentStr.includes('plugin_id')) {
    return 'nessus';
  }
  
  // OpenVAS detection
  if (lowerFilename.includes('openvas') || contentStr.includes('<get_results_response>') || contentStr.includes('openvas')) {
    return 'openvas';
  }
  
  // Qualys detection
  if (lowerFilename.includes('qualys') || contentStr.includes('SCAN_DATETIME') || contentStr.includes('QID')) {
    return 'qualys';
  }
  
  // Rapid7/Nexpose detection
  if (lowerFilename.includes('nexpose') || lowerFilename.includes('rapid7') || contentStr.includes('scan-id') || contentStr.includes('nexpose')) {
    return 'nexpose';
  }
  
  // Nmap detection
  if (lowerFilename.includes('nmap') || contentStr.includes('nmaprun') || contentStr.includes('vulners')) {
    return 'nmap';
  }
  
  // Nikto detection
  if (lowerFilename.includes('nikto') || contentStr.includes('Nikto') || contentStr.includes('OSVDB')) {
    return 'nikto';
  }
  
  // Burp Suite detection
  if (lowerFilename.includes('burp') || contentStr.includes('burp') || contentStr.includes('serialNumber')) {
    return 'burp';
  }
  
  // OWASP ZAP detection
  if (lowerFilename.includes('zap') || contentStr.includes('ZAP') || contentStr.includes('zaproxy')) {
    return 'zap';
  }
  
  // Acunetix detection
  if (lowerFilename.includes('acunetix') || contentStr.includes('acunetix') || contentStr.includes('ScanGroup')) {
    return 'acunetix';
  }
  
  // Generic detection based on file extension
  if (lowerFilename.endsWith('.json')) return 'json';
  if (lowerFilename.endsWith('.xml')) return 'xml';
  if (lowerFilename.endsWith('.csv')) return 'csv';
  
  return 'unknown';
};

export const parseNessusData = (data) => {
  const vulnerabilities = [];
  
  // Handle XML string format (raw .nessus file)
  if (typeof data === 'string') {
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(data, 'text/xml');
    
    // Check for parsing errors
    const parseError = xmlDoc.querySelector('parsererror');
    if (parseError) {
      throw new Error('Invalid XML format');
    }
    
    // Parse Nessus XML structure
    const reportHosts = xmlDoc.querySelectorAll('ReportHost');
    
    reportHosts.forEach(host => {
      const hostName = host.getAttribute('name') || 'Unknown';
      const reportItems = host.querySelectorAll('ReportItem');
      
      reportItems.forEach(item => {
        const pluginId = item.getAttribute('pluginID') || 'N/A';
        const pluginName = item.getAttribute('pluginName') || 'Unknown Vulnerability';
        const severity = item.getAttribute('severity') || '0';
        const port = item.getAttribute('port') || 'N/A';
        const protocol = item.getAttribute('protocol') || 'N/A';
        
        // Extract CVE from the item
        const cveElements = item.querySelectorAll('cve');
        const cveId = cveElements.length > 0 ? cveElements[0].textContent : pluginId;
        
        // Extract other details
        const description = getXMLText(item, 'description') || 
                          getXMLText(item, 'synopsis') || 
                          getXMLText(item, 'plugin_output') || 
                          'No description available';
        
        const riskFactor = getXMLText(item, 'risk_factor') || severity;
        const exploitAvailable = getXMLText(item, 'exploitability_ease')?.includes('Exploits are available') || 
                                getXMLText(item, 'exploit_available') === 'true' ||
                                getXMLText(item, 'exploited_by_nessus') === 'true';
        
        const cvssBaseScore = getXMLText(item, 'cvss_base_score') || 
                             getXMLText(item, 'cvss3_base_score') || 'N/A';
        
        const pluginPubDate = getXMLText(item, 'plugin_publication_date') || 
                             getXMLText(item, 'patch_publication_date') || 
                             new Date().toISOString();
        
        vulnerabilities.push({
          cveId: cveId,
          title: pluginName,
          description: description,
          severity: mapNessusSeverity(riskFactor || severity),
          asset: hostName,
          exploitAvailable: exploitAvailable,
          publishedDate: pluginPubDate,
          cvssScore: cvssBaseScore,
          port: port,
          protocol: protocol,
          pluginId: pluginId
        });
      });
    });
  }
  // Handle .nessus XML format (parsed object)
  else if (typeof data === 'object' && data.NessusClientData_v2) {
    const reports = data.NessusClientData_v2.Report;
    const reportsArray = Array.isArray(reports) ? reports : [reports];
    
    reportsArray.forEach(report => {
      if (report.ReportHost) {
        const hosts = Array.isArray(report.ReportHost) ? report.ReportHost : [report.ReportHost];
        hosts.forEach(host => {
          if (host.ReportItem) {
            const items = Array.isArray(host.ReportItem) ? host.ReportItem : [host.ReportItem];
            items.forEach(item => {
              vulnerabilities.push({
                cveId: item.cve || item.plugin_id || 'N/A',
                title: item.plugin_name || item.synopsis || 'Unknown Vulnerability',
                description: item.description || item.plugin_output || 'No description available',
                severity: mapNessusSeverity(item.severity || item.risk_factor),
                asset: host.name || 'Unknown',
                exploitAvailable: item.exploitability_ease === 'Exploits are available' || false,
                publishedDate: item.plugin_publication_date || new Date().toISOString(),
                cvssScore: item.cvss_base_score || item.cvss3_base_score || 'N/A',
                port: item.port || 'N/A',
                protocol: item.protocol || 'N/A',
                pluginId: item.plugin_id
              });
            });
          }
        });
      }
    });
  }
  // Handle JSON export format
  else if (data.vulnerabilities || Array.isArray(data)) {
    const vulns = data.vulnerabilities || data;
    vulnerabilities.push(...vulns.map(vuln => ({
      cveId: vuln.cve || vuln.plugin_id || 'N/A',
      title: vuln.name || vuln.plugin_name || 'Unknown Vulnerability',
      description: vuln.description || vuln.synopsis || 'No description available',
      severity: mapNessusSeverity(vuln.severity || vuln.risk_factor),
      asset: vuln.host || vuln.hostname || 'Unknown',
      exploitAvailable: vuln.exploit_available || vuln.exploitable || false,
      publishedDate: vuln.published || vuln.plugin_publication_date || new Date().toISOString(),
      cvssScore: vuln.cvss_score || vuln.cvss_base_score || 'N/A',
      port: vuln.port || 'N/A',
      protocol: vuln.protocol || 'N/A'
    })));
  }
  
  return vulnerabilities;
};

export const parseOpenVASData = (data) => {
  const vulnerabilities = [];
  
  // Handle XML format
  if (typeof data === 'string') {
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(data, 'text/xml');
    const results = xmlDoc.querySelectorAll('result');
    
    results.forEach(result => {
      const nvt = result.querySelector('nvt');
      vulnerabilities.push({
        cveId: getXMLText(result, 'nvt refs ref[type="cve"]') || 'N/A',
        title: getXMLText(result, 'nvt name') || 'Unknown Vulnerability',
        description: getXMLText(result, 'description') || getXMLText(result, 'nvt summary') || 'No description available',
        severity: mapOpenVASSeverity(getXMLText(result, 'severity')),
        asset: getXMLText(result, 'host') || 'Unknown',
        exploitAvailable: false, // OpenVAS doesn't typically include exploit info
        publishedDate: getXMLText(result, 'creation_time') || new Date().toISOString(),
        cvssScore: getXMLText(result, 'severity') || 'N/A',
        port: getXMLText(result, 'port') || 'N/A',
        oid: getXMLText(result, 'nvt oid')
      });
    });
  }
  // Handle JSON format
  else if (data.results) {
    vulnerabilities.push(...data.results.map(result => ({
      cveId: result.cve || result.nvt?.refs?.find(ref => ref.type === 'cve')?.id || 'N/A',
      title: result.name || result.nvt?.name || 'Unknown Vulnerability',
      description: result.description || result.nvt?.summary || 'No description available',
      severity: mapOpenVASSeverity(result.severity),
      asset: result.host || 'Unknown',
      exploitAvailable: false,
      publishedDate: result.creation_time || new Date().toISOString(),
      cvssScore: result.severity || 'N/A',
      port: result.port || 'N/A'
    })));
  }
  
  return vulnerabilities;
};

export const parseQualysData = (data) => {
  const vulnerabilities = [];
  
  if (data.SCAN && data.SCAN.IP) {
    const ips = Array.isArray(data.SCAN.IP) ? data.SCAN.IP : [data.SCAN.IP];
    
    ips.forEach(ip => {
      if (ip.VULN) {
        const vulns = Array.isArray(ip.VULN) ? ip.VULN : [ip.VULN];
        vulns.forEach(vuln => {
          vulnerabilities.push({
            cveId: vuln.CVE_ID || vuln.QID || 'N/A',
            title: vuln.TITLE || 'Unknown Vulnerability',
            description: vuln.DIAGNOSIS || vuln.CONSEQUENCE || 'No description available',
            severity: mapQualysSeverity(vuln.SEVERITY),
            asset: ip.value || ip.IP || 'Unknown',
            exploitAvailable: vuln.EXPLOITABILITY === 'Exploitable',
            publishedDate: vuln.FIRST_FOUND || new Date().toISOString(),
            cvssScore: vuln.CVSS_SCORE || vuln.CVSS_BASE || 'N/A',
            port: vuln.PORT || 'N/A',
            qid: vuln.QID
          });
        });
      }
    });
  }
  
  return vulnerabilities;
};

export const parseNmapData = (data) => {
  const vulnerabilities = [];
  
  if (data.nmaprun && data.nmaprun.host) {
    const hosts = Array.isArray(data.nmaprun.host) ? data.nmaprun.host : [data.nmaprun.host];
    
    hosts.forEach(host => {
      const hostAddr = host.address?.addr || 'Unknown';
      
      if (host.ports && host.ports.port) {
        const ports = Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port];
        
        ports.forEach(port => {
          if (port.script) {
            const scripts = Array.isArray(port.script) ? port.script : [port.script];
            
            scripts.forEach(script => {
              if (script.id === 'vulners' && script.output) {
                // Extract CVEs from vulners script output
                const cveMatches = script.output.match(/CVE-\d{4}-\d{4,}/g) || [];
                const scoreMatches = script.output.match(/(\d+\.\d+)\s+CVE-\d{4}-\d{4,}/g) || [];
                
                cveMatches.forEach((cve, index) => {
                  const scoreMatch = scoreMatches[index];
                  const score = scoreMatch ? scoreMatch.match(/(\d+\.\d+)/)[1] : 'N/A';
                  
                  vulnerabilities.push({
                    cveId: cve,
                    title: `Vulnerability on ${hostAddr}:${port.portid}`,
                    description: script.output,
                    severity: mapCVSSToSeverity(parseFloat(score)),
                    asset: hostAddr,
                    exploitAvailable: script.output.includes('exploit') || script.output.includes('metasploit'),
                    publishedDate: new Date().toISOString(),
                    cvssScore: score,
                    port: port.portid,
                    protocol: port.protocol,
                    service: port.service?.name || 'Unknown'
                  });
                });
              }
            });
          }
        });
      }
    });
  }
  
  return vulnerabilities;
};

export const parseNiktoData = (csvContent) => {
  const vulnerabilities = [];
  const lines = csvContent.split('\n');
  
  // Skip header line
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    
    const columns = line.split(',').map(col => col.replace(/"/g, '').trim());
    
    if (columns.length >= 6) {
      vulnerabilities.push({
        cveId: columns[5] || 'N/A', // OSVDB or CVE reference
        title: `Nikto Finding: ${columns[3]}`, // Method + URI
        description: columns[4] || 'No description available', // Description
        severity: 'Medium', // Nikto findings are typically medium severity
        asset: columns[0] || 'Unknown', // Host
        exploitAvailable: false,
        publishedDate: new Date().toISOString(),
        cvssScore: 'N/A',
        port: columns[1] || 'N/A', // Port
        uri: columns[3] || 'N/A' // URI
      });
    }
  }
  
  return vulnerabilities;
};

// Severity mapping functions
const mapNessusSeverity = (severity) => {
  if (!severity) return 'Unknown';
  const sev = severity.toString().toLowerCase();
  
  if (sev.includes('critical') || sev === '4') return 'Critical';
  if (sev.includes('high') || sev === '3') return 'High';
  if (sev.includes('medium') || sev === '2') return 'Medium';
  if (sev.includes('low') || sev === '1') return 'Low';
  if (sev.includes('info') || sev === '0') return 'Info';
  
  return 'Unknown';
};

const mapOpenVASSeverity = (severity) => {
  if (!severity) return 'Unknown';
  const score = parseFloat(severity);
  
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >= 0.1) return 'Low';
  
  return 'Info';
};

const mapQualysSeverity = (severity) => {
  if (!severity) return 'Unknown';
  const sev = severity.toString();
  
  if (sev === '5') return 'Critical';
  if (sev === '4') return 'High';
  if (sev === '3') return 'Medium';
  if (sev === '2') return 'Low';
  if (sev === '1') return 'Info';
  
  return 'Unknown';
};

const mapCVSSToSeverity = (score) => {
  if (!score || isNaN(score)) return 'Unknown';
  
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >= 0.1) return 'Low';
  
  return 'Info';
};

// Helper function for XML parsing
const getXMLText = (node, selector) => {
  const element = node.querySelector(selector);
  return element ? element.textContent.trim() : '';
};

export const parseUniversalScanner = (content, filename, fileType) => {
  const scannerType = detectScannerType(content, filename);
  
  try {
    switch (scannerType) {
      case 'nessus':
        return parseNessusData(content);
      case 'openvas':
        return parseOpenVASData(content);
      case 'qualys':
        return parseQualysData(content);
      case 'nmap':
        return parseNmapData(content);
      case 'nikto':
        return parseNiktoData(content);
      default:
        // Fall back to generic parsing
        if (fileType === 'json' || typeof content === 'object') {
          return parseGenericJSON(content);
        } else if (fileType === 'xml' || typeof content === 'string') {
          return parseGenericXML(content);
        } else if (fileType === 'csv') {
          return parseGenericCSV(content);
        }
        throw new Error(`Unsupported scanner type: ${scannerType}`);
    }
  } catch (error) {
    console.error(`Error parsing ${scannerType} data:`, error);
    throw new Error(`Failed to parse ${scannerType} scanner output: ${error.message}`);
  }
};

const parseGenericJSON = (data) => {
  // Generic JSON parsing logic (existing implementation)
  let vulnerabilities = [];
  
  if (data.vulnerabilities) {
    vulnerabilities = data.vulnerabilities;
  } else if (data.results) {
    vulnerabilities = data.results;
  } else if (Array.isArray(data)) {
    vulnerabilities = data;
  } else if (data.cve || data.cveId || data.id) {
    vulnerabilities = [data];
  }
  
  return vulnerabilities.map(vuln => ({
    cveId: vuln.cveId || vuln.cve_id || vuln.cve || vuln.id || 'N/A',
    title: vuln.title || vuln.name || vuln.summary || 'Unknown Vulnerability',
    description: vuln.description || vuln.details || 'No description available',
    severity: vuln.severity || 'Unknown',
    asset: vuln.asset || vuln.host || vuln.hostname || 'Unknown',
    exploitAvailable: vuln.exploitAvailable || vuln.exploit_available || false,
    publishedDate: vuln.publishedDate || vuln.published || new Date().toISOString(),
    cvssScore: vuln.cvssScore || vuln.cvss_score || 'N/A',
    port: vuln.port || 'N/A'
  }));
};

const parseGenericXML = (xmlContent) => {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlContent, 'text/xml');
  const vulnerabilities = [];
  
  // Try common XML vulnerability selectors
  const vulnSelectors = ['vulnerability', 'finding', 'result', 'vuln', 'issue'];
  
  for (const selector of vulnSelectors) {
    const nodes = xmlDoc.querySelectorAll(selector);
    if (nodes.length > 0) {
      nodes.forEach(node => {
        vulnerabilities.push({
          cveId: getXMLText(node, 'cve, cve_id, cve-id, id') || 'N/A',
          title: getXMLText(node, 'name, title, summary') || 'Unknown Vulnerability',
          description: getXMLText(node, 'description, details, synopsis') || 'No description available',
          severity: getXMLText(node, 'severity, risk, threat') || 'Unknown',
          asset: getXMLText(node, 'host, asset, target, hostname') || 'Unknown',
          exploitAvailable: getXMLText(node, 'exploit_available, exploitAvailable') === 'true',
          publishedDate: getXMLText(node, 'published, date, creation_time') || new Date().toISOString(),
          cvssScore: getXMLText(node, 'cvss_score, cvssScore, cvss') || 'N/A',
          port: getXMLText(node, 'port') || 'N/A'
        });
      });
      break; // Found vulnerabilities, stop trying other selectors
    }
  }
  
  return vulnerabilities;
};

const parseGenericCSV = (csvContent) => {
  const lines = csvContent.split('\n');
  const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, '').toLowerCase());
  const vulnerabilities = [];
  
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim()) {
      const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
      const vuln = {};
      
      headers.forEach((header, index) => {
        vuln[header] = values[index] || '';
      });
      
      vulnerabilities.push({
        cveId: vuln.cve || vuln.cve_id || vuln.cveid || vuln.id || 'N/A',
        title: vuln.title || vuln.name || vuln.summary || 'Unknown Vulnerability',
        description: vuln.description || vuln.details || 'No description available',
        severity: vuln.severity || vuln.risk || vuln.threat || 'Unknown',
        asset: vuln.asset || vuln.host || vuln.target || vuln.hostname || 'Unknown',
        exploitAvailable: vuln.exploit_available === 'true' || vuln.exploitavailable === 'true',
        publishedDate: vuln.published || vuln.date || new Date().toISOString(),
        cvssScore: vuln.cvss_score || vuln.cvssscore || vuln.cvss || 'N/A',
        port: vuln.port || 'N/A'
      });
    }
  }
  
  return vulnerabilities;
};