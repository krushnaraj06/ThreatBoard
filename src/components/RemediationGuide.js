import React, { useState } from 'react';
import { Shield, AlertTriangle, Clock, Target, ExternalLink, ChevronDown, ChevronUp, Download, Copy } from 'lucide-react';

const RemediationGuide = ({ vulnerability }) => {
  const [expandedSections, setExpandedSections] = useState(new Set(['immediate']));

  const toggleSection = (section) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(section)) {
      newExpanded.delete(section);
    } else {
      newExpanded.add(section);
    }
    setExpandedSections(newExpanded);
  };

  const generateDetailedRemediation = (vuln) => {
    const vulnText = `${vuln.title} ${vuln.description}`.toLowerCase();
    const remediation = {
      immediate: [],
      shortTerm: [],
      longTerm: [],
      prevention: [],
      monitoring: []
    };

    // Immediate actions based on vulnerability type
    if (vuln.exploitAvailable) {
      remediation.immediate.push({
        action: 'Emergency Patching',
        description: 'Apply security patches immediately as public exploits are available',
        priority: 'CRITICAL',
        timeframe: '< 4 hours',
        commands: [
          '# Check current version',
          'systemctl status [service-name]',
          '# Apply emergency patch',
          'yum update [package-name] -y',
          '# Restart service',
          'systemctl restart [service-name]'
        ]
      });
      
      remediation.immediate.push({
        action: 'Network Isolation',
        description: 'Temporarily isolate affected systems from network if patching is not immediately possible',
        priority: 'CRITICAL',
        timeframe: '< 1 hour',
        commands: [
          '# Block traffic to affected service',
          'iptables -A INPUT -p tcp --dport [port] -j DROP',
          '# Or disable service temporarily',
          'systemctl stop [service-name]'
        ]
      });
    }

    // Technology-specific remediation
    if (vulnText.includes('apache') || vulnText.includes('httpd')) {
      remediation.immediate.push({
        action: 'Apache Web Server Update',
        description: 'Update Apache to the latest stable version and review configuration',
        priority: 'HIGH',
        timeframe: '< 24 hours',
        commands: [
          '# Update Apache (CentOS/RHEL)',
          'yum update httpd -y',
          '# Update Apache (Ubuntu/Debian)',
          'apt-get update && apt-get upgrade apache2 -y',
          '# Restart Apache',
          'systemctl restart httpd',
          '# Verify version',
          'httpd -v'
        ]
      });

      remediation.shortTerm.push({
        action: 'Apache Security Hardening',
        description: 'Implement security best practices for Apache configuration',
        priority: 'HIGH',
        timeframe: '1-3 days',
        commands: [
          '# Hide Apache version',
          'echo "ServerTokens Prod" >> /etc/httpd/conf/httpd.conf',
          'echo "ServerSignature Off" >> /etc/httpd/conf/httpd.conf',
          '# Disable unnecessary modules',
          'a2dismod status',
          'a2dismod info'
        ]
      });
    }

    if (vulnText.includes('nginx')) {
      remediation.immediate.push({
        action: 'Nginx Update',
        description: 'Update Nginx to the latest stable version',
        priority: 'HIGH',
        timeframe: '< 24 hours',
        commands: [
          '# Update Nginx (CentOS/RHEL)',
          'yum update nginx -y',
          '# Update Nginx (Ubuntu/Debian)',
          'apt-get update && apt-get upgrade nginx -y',
          '# Test configuration',
          'nginx -t',
          '# Reload Nginx',
          'systemctl reload nginx'
        ]
      });
    }

    if (vulnText.includes('mysql') || vulnText.includes('mariadb')) {
      remediation.immediate.push({
        action: 'Database Server Update',
        description: 'Update MySQL/MariaDB and review access controls',
        priority: 'HIGH',
        timeframe: '< 24 hours',
        commands: [
          '# Update MySQL (CentOS/RHEL)',
          'yum update mysql-server -y',
          '# Update MariaDB (Ubuntu/Debian)',
          'apt-get update && apt-get upgrade mariadb-server -y',
          '# Restart database',
          'systemctl restart mysqld',
          '# Run security script',
          'mysql_secure_installation'
        ]
      });

      remediation.shortTerm.push({
        action: 'Database Security Review',
        description: 'Review and strengthen database access controls and configuration',
        priority: 'HIGH',
        timeframe: '1-3 days',
        commands: [
          '# Review user privileges',
          'SELECT User, Host FROM mysql.user;',
          '# Remove anonymous users',
          'DELETE FROM mysql.user WHERE User="";',
          '# Remove test database',
          'DROP DATABASE IF EXISTS test;',
          '# Flush privileges',
          'FLUSH PRIVILEGES;'
        ]
      });
    }

    if (vulnText.includes('docker') || vulnText.includes('container')) {
      remediation.immediate.push({
        action: 'Container Runtime Update',
        description: 'Update Docker/container runtime and base images',
        priority: 'HIGH',
        timeframe: '< 24 hours',
        commands: [
          '# Update Docker',
          'yum update docker-ce -y',
          '# Or for Ubuntu',
          'apt-get update && apt-get upgrade docker-ce -y',
          '# Pull latest base images',
          'docker pull [base-image]:latest',
          '# Rebuild containers',
          'docker-compose up --build -d'
        ]
      });

      remediation.longTerm.push({
        action: 'Container Security Implementation',
        description: 'Implement comprehensive container security practices',
        priority: 'MEDIUM',
        timeframe: '1-2 weeks',
        commands: [
          '# Scan images for vulnerabilities',
          'docker scan [image-name]',
          '# Use non-root user in containers',
          'USER 1001',
          '# Implement resource limits',
          'docker run --memory=512m --cpus=1 [image]'
        ]
      });
    }

    // SQL Injection specific remediation
    if (vulnText.includes('sql injection')) {
      remediation.immediate.push({
        action: 'SQL Injection Mitigation',
        description: 'Implement immediate protections against SQL injection attacks',
        priority: 'CRITICAL',
        timeframe: '< 4 hours',
        commands: [
          '# Enable WAF rules for SQL injection',
          'ModSecurity: Enable SQL injection rules',
          '# Review and sanitize database queries',
          '# Implement parameterized queries',
          '# Disable dangerous SQL functions if possible'
        ]
      });

      remediation.shortTerm.push({
        action: 'Code Review and Remediation',
        description: 'Review application code and implement secure coding practices',
        priority: 'HIGH',
        timeframe: '1-3 days',
        commands: [
          '# Use prepared statements (PHP example)',
          '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");',
          '$stmt->execute([$user_id]);',
          '# Input validation and sanitization',
          '$clean_input = filter_var($input, FILTER_SANITIZE_STRING);'
        ]
      });
    }

    // Authentication bypass remediation
    if (vulnText.includes('authentication') || vulnText.includes('bypass')) {
      remediation.immediate.push({
        action: 'Authentication Strengthening',
        description: 'Implement stronger authentication mechanisms immediately',
        priority: 'CRITICAL',
        timeframe: '< 4 hours',
        commands: [
          '# Force password reset for all users',
          '# Enable account lockout policies',
          '# Implement multi-factor authentication',
          '# Review and revoke suspicious sessions'
        ]
      });
    }

    // Generic remediation for all vulnerabilities
    remediation.shortTerm.push({
      action: 'Security Monitoring Enhancement',
      description: 'Implement enhanced monitoring and alerting for the affected system',
      priority: 'MEDIUM',
      timeframe: '3-7 days',
      commands: [
        '# Install and configure log monitoring',
        'yum install rsyslog -y',
        '# Configure log forwarding to SIEM',
        '# Set up alerting for suspicious activities',
        '# Implement file integrity monitoring'
      ]
    });

    remediation.longTerm.push({
      action: 'Vulnerability Management Process',
      description: 'Establish ongoing vulnerability management and patch management processes',
      priority: 'MEDIUM',
      timeframe: '2-4 weeks',
      commands: [
        '# Implement automated vulnerability scanning',
        '# Set up patch management system',
        '# Create incident response procedures',
        '# Establish security awareness training'
      ]
    });

    remediation.prevention.push({
      action: 'Preventive Security Measures',
      description: 'Implement measures to prevent similar vulnerabilities in the future',
      priority: 'LOW',
      timeframe: 'Ongoing',
      commands: [
        '# Regular security assessments',
        '# Implement DevSecOps practices',
        '# Code security reviews',
        '# Security architecture reviews'
      ]
    });

    return remediation;
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const remediation = generateDetailedRemediation(vulnerability);

  const getSectionIcon = (section) => {
    switch (section) {
      case 'immediate': return <AlertTriangle className="h-5 w-5 text-red-600" />;
      case 'shortTerm': return <Clock className="h-5 w-5 text-orange-600" />;
      case 'longTerm': return <Target className="h-5 w-5 text-blue-600" />;
      case 'prevention': return <Shield className="h-5 w-5 text-green-600" />;
      case 'monitoring': return <Target className="h-5 w-5 text-purple-600" />;
      default: return <Shield className="h-5 w-5 text-gray-600" />;
    }
  };

  const getSectionTitle = (section) => {
    switch (section) {
      case 'immediate': return 'Immediate Actions (0-24 hours)';
      case 'shortTerm': return 'Short-term Actions (1-7 days)';
      case 'longTerm': return 'Long-term Actions (1-4 weeks)';
      case 'prevention': return 'Prevention & Best Practices';
      case 'monitoring': return 'Monitoring & Detection';
      default: return section;
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'CRITICAL': return 'bg-red-100 text-red-800 border-red-200';
      case 'HIGH': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'MEDIUM': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'LOW': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-xl font-bold text-gray-900 flex items-center">
          <Shield className="h-6 w-6 text-green-600 mr-2" />
          Comprehensive Remediation Guide
        </h3>
        <div className="flex gap-2">
          <button className="inline-flex items-center px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
            <Download className="h-4 w-4 mr-2" />
            Export Guide
          </button>
          <a
            href={`https://nvd.nist.gov/vuln/detail/${vulnerability.cveId}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center px-3 py-2 text-sm font-medium text-blue-700 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100"
          >
            <ExternalLink className="h-4 w-4 mr-2" />
            View NVD Details
          </a>
        </div>
      </div>

      <div className="mb-6 p-4 bg-gray-50 rounded-lg">
        <h4 className="font-semibold text-gray-900 mb-2">Vulnerability Summary</h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div>
            <span className="text-gray-600">CVE ID:</span>
            <span className="ml-2 font-mono font-medium">{vulnerability.cveId}</span>
          </div>
          <div>
            <span className="text-gray-600">Severity:</span>
            <span className={`ml-2 px-2 py-1 text-xs font-semibold rounded-full ${
              vulnerability.severity === 'Critical' ? 'bg-red-100 text-red-800' :
              vulnerability.severity === 'High' ? 'bg-orange-100 text-orange-800' :
              vulnerability.severity === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
              'bg-green-100 text-green-800'
            }`}>
              {vulnerability.severity}
            </span>
          </div>
          <div>
            <span className="text-gray-600">Asset:</span>
            <span className="ml-2 font-medium">{vulnerability.asset}</span>
          </div>
        </div>
      </div>

      {/* Remediation Sections */}
      <div className="space-y-4">
        {Object.entries(remediation).map(([section, actions]) => {
          if (actions.length === 0) return null;
          
          return (
            <div key={section} className="border border-gray-200 rounded-lg overflow-hidden">
              <button
                onClick={() => toggleSection(section)}
                className="w-full px-4 py-3 bg-gray-50 hover:bg-gray-100 flex items-center justify-between text-left"
              >
                <div className="flex items-center">
                  {getSectionIcon(section)}
                  <span className="ml-3 font-semibold text-gray-900">
                    {getSectionTitle(section)}
                  </span>
                  <span className="ml-2 px-2 py-1 text-xs bg-gray-200 text-gray-700 rounded-full">
                    {actions.length} action{actions.length !== 1 ? 's' : ''}
                  </span>
                </div>
                {expandedSections.has(section) ? (
                  <ChevronUp className="h-5 w-5 text-gray-400" />
                ) : (
                  <ChevronDown className="h-5 w-5 text-gray-400" />
                )}
              </button>

              {expandedSections.has(section) && (
                <div className="p-4 space-y-4">
                  {actions.map((action, index) => (
                    <div key={index} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <h5 className="font-semibold text-gray-900">{action.action}</h5>
                            <span className={`px-2 py-1 text-xs font-semibold rounded border ${getPriorityColor(action.priority)}`}>
                              {action.priority}
                            </span>
                            <span className="text-xs text-gray-500">
                              ⏱️ {action.timeframe}
                            </span>
                          </div>
                          <p className="text-sm text-gray-700 mb-3">{action.description}</p>
                        </div>
                      </div>

                      {action.commands && action.commands.length > 0 && (
                        <div className="bg-gray-900 rounded-lg p-3">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-medium text-gray-300">Commands</span>
                            <button
                              onClick={() => copyToClipboard(action.commands.join('\n'))}
                              className="text-xs text-gray-400 hover:text-gray-200 flex items-center"
                            >
                              <Copy className="h-3 w-3 mr-1" />
                              Copy
                            </button>
                          </div>
                          <pre className="text-sm text-green-400 font-mono overflow-x-auto">
                            {action.commands.join('\n')}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Additional Resources */}
      <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
        <h4 className="font-semibold text-blue-900 mb-2">Additional Resources</h4>
        <div className="space-y-2 text-sm text-blue-800">
          <div>• <strong>NIST Cybersecurity Framework:</strong> Implement comprehensive security controls</div>
          <div>• <strong>OWASP Security Guidelines:</strong> Follow web application security best practices</div>
          <div>• <strong>Vendor Security Advisories:</strong> Subscribe to security updates from affected vendors</div>
          <div>• <strong>CERT/CC Vulnerability Notes:</strong> Review detailed vulnerability analysis and mitigation strategies</div>
        </div>
      </div>
    </div>
  );
};

export default RemediationGuide;