import React from 'react';
import { AlertTriangle, TrendingUp, Shield, Activity, Target, Clock } from 'lucide-react';

const SummaryCards = ({ vulnerabilities }) => {
  const getSeverityCounts = () => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    vulnerabilities.forEach(vuln => {
      if (counts.hasOwnProperty(vuln.severity)) {
        counts[vuln.severity]++;
      }
    });
    return counts;
  };

  const getTopUrgentVulnerabilities = () => {
    return vulnerabilities
      .filter(vuln => vuln.severity === 'Critical' || vuln.severity === 'High')
      .sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0))
      .slice(0, 3);
  };

  const getAverageRiskScore = () => {
    const scores = vulnerabilities.map(v => v.riskScore || 0).filter(score => score > 0);
    if (scores.length === 0) return 0;
    return Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length);
  };

  const getExploitCount = () => {
    return vulnerabilities.filter(vuln => vuln.exploitAvailable).length;
  };

  const severityCounts = getSeverityCounts();
  const topUrgent = getTopUrgentVulnerabilities();
  const averageRiskScore = getAverageRiskScore();
  const exploitCount = getExploitCount();

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'High': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'Medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'Low': return 'text-green-600 bg-green-50 border-green-200';
      case 'Info': return 'text-blue-600 bg-blue-50 border-blue-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getRiskScoreColor = (score) => {
    if (score >= 80) return 'text-red-600';
    if (score >= 60) return 'text-orange-600';
    if (score >= 40) return 'text-yellow-600';
    if (score >= 20) return 'text-green-600';
    return 'text-gray-600';
  };

  const getRiskScoreBgColor = (score) => {
    if (score >= 80) return 'bg-red-100';
    if (score >= 60) return 'bg-orange-100';
    if (score >= 40) return 'bg-yellow-100';
    if (score >= 20) return 'bg-green-100';
    return 'bg-gray-100';
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {/* Total Vulnerabilities */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center">
          <div className="p-2 bg-blue-100 rounded-lg">
            <Shield className="h-6 w-6 text-blue-600" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-gray-600">Total Vulnerabilities</p>
            <p className="text-2xl font-bold text-gray-900">{vulnerabilities.length}</p>
          </div>
        </div>
        <div className="mt-4">
          <div className="flex items-center text-sm text-gray-500">
            <TrendingUp className="h-4 w-4 mr-1" />
            <span>Uploaded from scanner</span>
          </div>
        </div>
      </div>

      {/* Average Risk Score */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center">
          <div className="p-2 bg-red-100 rounded-lg">
            <AlertTriangle className="h-6 w-6 text-red-600" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-gray-600">Average Risk Score</p>
            <p className={`text-2xl font-bold ${getRiskScoreColor(averageRiskScore)}`}>
              {averageRiskScore}/100
            </p>
          </div>
        </div>
        <div className="mt-4">
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div 
              className={`h-2 rounded-full ${getRiskScoreBgColor(averageRiskScore)}`}
              style={{ width: `${averageRiskScore}%` }}
            ></div>
          </div>
        </div>
      </div>

      {/* Exploit Available */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center">
          <div className="p-2 bg-orange-100 rounded-lg">
            <Target className="h-6 w-6 text-orange-600" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-gray-600">Exploit Available</p>
            <p className="text-2xl font-bold text-orange-600">{exploitCount}</p>
          </div>
        </div>
        <div className="mt-4">
          <div className="flex items-center text-sm text-gray-500">
            <Activity className="h-4 w-4 mr-1" />
            <span>High priority targets</span>
          </div>
        </div>
      </div>

      {/* Critical & High Count */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center">
          <div className="p-2 bg-red-100 rounded-lg">
            <AlertTriangle className="h-6 w-6 text-red-600" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-gray-600">Critical & High</p>
            <p className="text-2xl font-bold text-red-600">
              {severityCounts.Critical + severityCounts.High}
            </p>
          </div>
        </div>
        <div className="mt-4">
          <div className="flex items-center text-sm text-gray-500">
            <Clock className="h-4 w-4 mr-1" />
            <span>Immediate attention required</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SummaryCards;
