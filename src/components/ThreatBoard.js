import React, { useState } from 'react';
import SearchForm from './SearchForm';
import ResultsTable from './ResultsTable';
import LoadingSpinner from './LoadingSpinner';
import ErrorMessage from './ErrorMessage';

const ThreatBoard = () => {
  const [searchResults, setSearchResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [hasSearched, setHasSearched] = useState(false);

  const handleSearch = async (technology) => {
    setLoading(true);
    setError(null);
    setHasSearched(true);

    try {
      const response = await fetch(`http://localhost:5000/cves/${encodeURIComponent(technology)}`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      setSearchResults(data);
    } catch (err) {
      setError(err.message || 'Failed to fetch CVE data');
      setSearchResults([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadReport = () => {
    // Placeholder for future download functionality
    alert('Download Report feature coming soon!');
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <h1 className="text-3xl font-bold text-gray-900">
              ThreatBoard – Vulnerability Dashboard
            </h1>
            {hasSearched && searchResults.length > 0 && (
              <button
                onClick={handleDownloadReport}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 transition-colors duration-200"
              >
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Download Report
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Search Form */}
        <div className="mb-8">
          <SearchForm onSearch={handleSearch} />
        </div>

        {/* Loading State */}
        {loading && (
          <div className="flex justify-center items-center py-12">
            <LoadingSpinner />
          </div>
        )}

        {/* Error State */}
        {error && !loading && (
          <div className="mb-8">
            <ErrorMessage message={error} />
          </div>
        )}

        {/* Results */}
        {!loading && !error && hasSearched && (
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <ResultsTable results={searchResults} />
          </div>
        )}

        {/* No Results */}
        {!loading && !error && hasSearched && searchResults.length === 0 && (
          <div className="text-center py-12">
            <div className="text-gray-500 text-lg font-medium">
              No vulnerabilities found for this technology.
            </div>
            <p className="text-gray-400 mt-2">
              Try searching for a different technology or check the spelling.
            </p>
          </div>
        )}
      </main>
    </div>
  );
};

export default ThreatBoard;
