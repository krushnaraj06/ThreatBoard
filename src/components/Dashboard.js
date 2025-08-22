import React, { useState, useEffect } from 'react';
import Sidebar from './Sidebar';
import CVETable from './CVETable';
import SeverityPieChart from './SeverityPieChart';
import YearlyBarChart from './YearlyBarChart';
import SearchBar from './SearchBar';

const Dashboard = () => {
  const [cveData, setCveData] = useState([]);
  const [filteredData, setFilteredData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Filter states
  const [severityFilter, setSeverityFilter] = useState('all');
  const [yearRange, setYearRange] = useState([2020, new Date().getFullYear()]);
  const [searchQuery, setSearchQuery] = useState('');
  
  // Pagination states
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);

  // Fetch CVE data
  useEffect(() => {
    fetchCVEData();
  }, []);

  const fetchCVEData = async () => {
    try {
      setLoading(true);
      // For now, we'll use mock data since the backend endpoint is /cves/:tech
      // You can replace this with actual API call when ready
      const mockData = generateMockCVEData();
      setCveData(mockData);
      setFilteredData(mockData);
    } catch (err) {
      setError('Failed to fetch CVE data');
      console.error('Error fetching CVE data:', err);
    } finally {
      setLoading(false);
    }
  };

  // Generate mock data for demonstration
  const generateMockCVEData = () => {
    const severities = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
    const technologies = ['React', 'Node.js', 'MySQL', 'WordPress', 'Django'];
    const years = [2020, 2021, 2022, 2023, 2024];
    
    const mockData = [];
    
    for (let i = 1; i <= 50; i++) {
      const year = years[Math.floor(Math.random() * years.length)];
      const severity = severities[Math.floor(Math.random() * severities.length)];
      const tech = technologies[Math.floor(Math.random() * technologies.length)];
      
      mockData.push({
        id: `CVE-${year}-${String(i).padStart(4, '0')}`,
        description: `This is a ${severity.toLowerCase()} severity vulnerability in ${tech} that could allow attackers to ${getRandomVulnerabilityDescription()}. The issue affects versions ${getRandomVersion()} and requires immediate attention.`,
        severity: severity,
        publishedDate: `${year}-${String(Math.floor(Math.random() * 12) + 1).padStart(2, '0')}-${String(Math.floor(Math.random() * 28) + 1).padStart(2, '0')}`,
        technology: tech,
        cvssScore: severity === 'Critical' ? Math.floor(Math.random() * 2) + 9 : 
                   severity === 'High' ? Math.floor(Math.random() * 2) + 7 :
                   severity === 'Medium' ? Math.floor(Math.random() * 2) + 5 :
                   severity === 'Low' ? Math.floor(Math.random() * 2) + 3 : 0
      });
    }
    
    return mockData;
  };

  const getRandomVulnerabilityDescription = () => {
    const descriptions = [
      'execute arbitrary code',
      'gain unauthorized access',
      'cause denial of service',
      'access sensitive information',
      'escalate privileges',
      'bypass security controls'
    ];
    return descriptions[Math.floor(Math.random() * descriptions.length)];
  };

  const getRandomVersion = () => {
    const major = Math.floor(Math.random() * 5) + 1;
    const minor = Math.floor(Math.random() * 10);
    const patch = Math.floor(Math.random() * 10);
    return `${major}.${minor}.${patch}`;
  };

  // Apply filters and search
  useEffect(() => {
    let filtered = [...cveData];

    // Apply severity filter
    if (severityFilter !== 'all') {
      filtered = filtered.filter(cve => cve.severity === severityFilter);
    }

    // Apply year range filter
    filtered = filtered.filter(cve => {
      const year = new Date(cve.publishedDate).getFullYear();
      return year >= yearRange[0] && year <= yearRange[1];
    });

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(cve => 
        cve.id.toLowerCase().includes(query) ||
        cve.description.toLowerCase().includes(query) ||
        cve.technology.toLowerCase().includes(query)
      );
    }

    setFilteredData(filtered);
    setCurrentPage(1); // Reset to first page when filters change
  }, [cveData, severityFilter, yearRange, searchQuery]);

  // Calculate pagination
  const indexOfLastItem = currentPage * itemsPerPage;
  const indexOfFirstItem = indexOfLastItem - itemsPerPage;
  const currentItems = filteredData.slice(indexOfFirstItem, indexOfLastItem);
  const totalPages = Math.ceil(filteredData.length / itemsPerPage);

  const handlePageChange = (pageNumber) => {
    setCurrentPage(pageNumber);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-red-600 text-lg">{error}</div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <Sidebar
        severityFilter={severityFilter}
        setSeverityFilter={setSeverityFilter}
        yearRange={yearRange}
        setYearRange={setYearRange}
        totalCVEs={filteredData.length}
      />

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="bg-white shadow-sm border-b border-gray-200 px-6 py-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <h1 className="text-2xl font-bold text-gray-900">
              CVE Dashboard
            </h1>
            <SearchBar
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              placeholder="Search CVEs, descriptions, or technologies..."
            />
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-6">
          <div className="space-y-6">
            {/* Charts Section */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Severity Distribution Pie Chart */}
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <h2 className="text-lg font-semibold text-gray-900 mb-4">
                  CVE Distribution by Severity
                </h2>
                <SeverityPieChart data={filteredData} />
              </div>

              {/* Yearly CVE Count Bar Chart */}
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <h2 className="text-lg font-semibold text-gray-900 mb-4">
                  CVEs per Year
                </h2>
                <YearlyBarChart data={filteredData} />
              </div>
            </div>

            {/* CVE Table */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900">
                  CVE Details
                </h2>
                <p className="text-sm text-gray-600 mt-1">
                  Showing {filteredData.length} vulnerabilities
                </p>
              </div>
              <CVETable
                data={currentItems}
                currentPage={currentPage}
                totalPages={totalPages}
                onPageChange={handlePageChange}
                itemsPerPage={itemsPerPage}
                totalItems={filteredData.length}
              />
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default Dashboard;
