import React from 'react';

const Sidebar = ({ severityFilter, setSeverityFilter, yearRange, setYearRange, totalCVEs }) => {
  const currentYear = new Date().getFullYear();
  const minYear = 2010;
  const maxYear = currentYear;

  const handleYearRangeChange = (e, index) => {
    const newRange = [...yearRange];
    newRange[index] = parseInt(e.target.value);
    
    // Ensure min year doesn't exceed max year
    if (index === 0 && newRange[0] > newRange[1]) {
      newRange[1] = newRange[0];
    }
    // Ensure max year doesn't go below min year
    if (index === 1 && newRange[1] < newRange[0]) {
      newRange[0] = newRange[1];
    }
    
    setYearRange(newRange);
  };

  return (
    <div className="w-64 bg-white shadow-sm border-r border-gray-200 flex flex-col">
      {/* Header */}
      <div className="p-6 border-b border-gray-200">
        <h2 className="text-lg font-semibold text-gray-900">Filters</h2>
        <p className="text-sm text-gray-600 mt-1">
          {totalCVEs} vulnerabilities found
        </p>
      </div>

      {/* Filters */}
      <div className="flex-1 p-6 space-y-6">
        {/* Severity Filter */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-3">
            Severity Level
          </label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors duration-200"
          >
            <option value="all">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Unknown">Unknown</option>
          </select>
        </div>

        {/* Year Range Filter */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-3">
            Year Range
          </label>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-gray-500 mb-1">From</label>
              <input
                type="range"
                min={minYear}
                max={maxYear}
                value={yearRange[0]}
                onChange={(e) => handleYearRangeChange(e, 0)}
                className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
              />
              <div className="flex justify-between text-xs text-gray-500 mt-1">
                <span>{minYear}</span>
                <span className="font-medium">{yearRange[0]}</span>
                <span>{maxYear}</span>
              </div>
            </div>
            
            <div>
              <label className="block text-xs text-gray-500 mb-1">To</label>
              <input
                type="range"
                min={minYear}
                max={maxYear}
                value={yearRange[1]}
                onChange={(e) => handleYearRangeChange(e, 1)}
                className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
              />
              <div className="flex justify-between text-xs text-gray-500 mt-1">
                <span>{minYear}</span>
                <span className="font-medium">{yearRange[1]}</span>
                <span>{maxYear}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="pt-4 border-t border-gray-200">
          <h3 className="text-sm font-medium text-gray-700 mb-3">Quick Stats</h3>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Critical:</span>
              <span className="font-medium text-red-600">High Priority</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">High:</span>
              <span className="font-medium text-orange-600">Medium Priority</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Medium:</span>
              <span className="font-medium text-yellow-600">Low Priority</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Low:</span>
              <span className="font-medium text-green-600">Info Only</span>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="p-6 border-t border-gray-200">
        <div className="text-center">
          <p className="text-xs text-gray-500">
            Data from National Vulnerability Database
          </p>
          <p className="text-xs text-gray-400 mt-1">
            Updated in real-time
          </p>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
