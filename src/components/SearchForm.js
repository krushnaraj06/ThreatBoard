import React, { useState } from 'react';

const SearchForm = ({ onSearch }) => {
  const [technology, setTechnology] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (technology.trim()) {
      onSearch(technology.trim());
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="technology" className="block text-sm font-medium text-gray-700 mb-2">
            Search for Technology Vulnerabilities
          </label>
          <div className="flex gap-3">
            <input
              type="text"
              id="technology"
              value={technology}
              onChange={(e) => setTechnology(e.target.value)}
              placeholder="Enter technology name (e.g., React, Node.js, MySQL, WordPress)"
              className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors duration-200 placeholder-gray-400"
              required
            />
            <button
              type="submit"
              className="px-6 py-3 bg-primary-600 text-white font-medium rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 transition-colors duration-200 flex items-center gap-2"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              Search CVEs
            </button>
          </div>
        </div>
        <p className="text-sm text-gray-500">
          Search for Common Vulnerabilities and Exposures (CVEs) related to specific technologies, frameworks, or software.
        </p>
      </form>
    </div>
  );
};

export default SearchForm;
