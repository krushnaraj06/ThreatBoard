import React from 'react';

const LoadingSpinner = () => {
  return (
    <div className="flex flex-col items-center space-y-4">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      <div className="text-gray-600 font-medium">Searching for vulnerabilities...</div>
      <div className="text-sm text-gray-500">This may take a few moments</div>
    </div>
  );
};

export default LoadingSpinner;
