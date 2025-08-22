import React from 'react';

const ResultsTable = ({ results }) => {
  if (!results || results.length === 0) {
    return null;
  }

  const getSeverityColor = (severity) => {
    if (!severity) return 'bg-gray-100 text-gray-800';
    
    const severityLower = severity.toLowerCase();
    if (severityLower.includes('critical') || severityLower.includes('high')) {
      return 'bg-red-100 text-red-800';
    } else if (severityLower.includes('medium')) {
      return 'bg-yellow-100 text-yellow-800';
    } else if (severityLower.includes('low')) {
      return 'bg-green-100 text-green-800';
    }
    return 'bg-gray-100 text-gray-800';
  };

  const getNvdUrl = (cveId) => {
    return `https://nvd.nist.gov/vuln/detail/${cveId}`;
  };

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              CVE ID
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Description
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Severity
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Published Date
            </th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {results.map((cve, index) => (
            <tr key={cve.id || index} className="hover:bg-gray-50 transition-colors duration-150">
              <td className="px-6 py-4 whitespace-nowrap">
                <a
                  href={getNvdUrl(cve.id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary-600 hover:text-primary-800 font-mono text-sm font-medium hover:underline"
                >
                  {cve.id}
                </a>
              </td>
              <td className="px-6 py-4">
                <div className="text-sm text-gray-900 max-w-md">
                  {cve.description || cve.summary || 'No description available'}
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                {cve.severity ? (
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(cve.severity)}`}>
                    {cve.severity}
                  </span>
                ) : (
                  <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-gray-100 text-gray-800">
                    Unknown
                  </span>
                )}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {cve.publishedDate ? new Date(cve.publishedDate).toLocaleDateString() : 'N/A'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ResultsTable;
