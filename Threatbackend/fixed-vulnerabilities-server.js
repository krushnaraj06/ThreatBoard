const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Helper function to extract severity from CVSS metrics
const extractSeverity = (metrics) => {
  if (!metrics) return 'N/A';
  
  // Try CVSS v3.1 first
  if (metrics.cvssMetricV31 && metrics.cvssMetricV31[0]) {
    return metrics.cvssMetricV31[0].cvssData.baseSeverity || 'N/A';
  }
  
  // Try CVSS v3.0
  if (metrics.cvssMetricV30 && metrics.cvssMetricV30[0]) {
    return metrics.cvssMetricV30[0].cvssData.baseSeverity || 'N/A';
  }
  
  // Try CVSS v2
  if (metrics.cvssMetricV2 && metrics.cvssMetricV2[0]) {
    const score = metrics.cvssMetricV2[0].cvssData.baseScore;
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 0.1) return 'Low';
  }
  
  return 'N/A';
};

// Helper function to format date
const formatDate = (dateString) => {
  if (!dateString) return 'N/A';
  
  try {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-GB', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    });
  } catch (error) {
    return 'N/A';
  }
};

// Helper function to clean and normalize CVE data
const normalizeCVE = (cveItem) => {
  const cve = cveItem.cve;
  
  return {
    cveId: cve.id || 'N/A',
    description: cve.descriptions?.[0]?.value || 'No description available',
    severity: extractSeverity(cve.metrics),
    publishedDate: formatDate(cve.published)
  };
};

// Main vulnerabilities endpoint
app.get('/api/vulnerabilities', async (req, res) => {
  try {
    const { query } = req.query;
    
    // Validate query parameter
    if (!query || query.trim() === '') {
      return res.status(400).json({
        error: 'Query parameter is required',
        message: 'Please provide a search query (e.g., ?query=wordpress)'
      });
    }
    
    console.log(`Searching for vulnerabilities with query: "${query}"`);
    
    // Build NVD API URL
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query.trim())}`;
    
    // Call NVD API
    const response = await axios.get(nvdUrl, {
      headers: {
        'User-Agent': 'ThreatBoard/1.0 (Security Research Tool)'
      },
      timeout: 15000 // 15 second timeout
    });
    
    // Extract vulnerabilities from response
    const vulnerabilities = response.data.vulnerabilities || [];
    
    if (vulnerabilities.length === 0) {
      console.log(`No vulnerabilities found for query: "${query}"`);
      return res.json({
        query: query,
        count: 0,
        vulnerabilities: [],
        message: 'No vulnerabilities found for the specified query'
      });
    }
    
    // Normalize and clean the data
    const cleanedVulnerabilities = vulnerabilities.map(normalizeCVE);
    
    console.log(`Found ${cleanedVulnerabilities.length} vulnerabilities for query: "${query}"`);
    
    // Send clean response
    res.json({
      query: query,
      count: cleanedVulnerabilities.length,
      vulnerabilities: cleanedVulnerabilities
    });
    
  } catch (error) {
    console.error('Error fetching vulnerabilities:', error.message);
    
    let errorMessage = 'Failed to fetch vulnerability data';
    let statusCode = 500;
    
    if (error.code === 'ECONNABORTED') {
      errorMessage = 'Request timeout - NVD API is taking too long to respond';
      statusCode = 408;
    } else if (error.response) {
      statusCode = error.response.status;
      if (error.response.status === 404) {
        errorMessage = 'No vulnerabilities found for the specified query';
        statusCode = 200; // Return 200 with empty array instead of 404
      } else if (error.response.status === 429) {
        errorMessage = 'Rate limit exceeded - please try again later';
        statusCode = 429;
      } else {
        errorMessage = `NVD API error: ${error.response.status}`;
      }
    } else if (error.request) {
      errorMessage = 'No response from NVD API - please check your internet connection';
      statusCode = 503;
    }
    
    res.status(statusCode).json({
      error: errorMessage,
      query: req.query.query || 'unknown',
      timestamp: new Date().toISOString()
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'ThreatBoard Vulnerabilities Backend is running',
    timestamp: new Date().toISOString(),
    endpoint: '/api/vulnerabilities'
  });
});

// Root endpoint with API info
app.get('/', (req, res) => {
  res.json({
    message: 'ThreatBoard Vulnerabilities API',
    version: '1.0.0',
    endpoint: 'GET /api/vulnerabilities?query={search_term}',
    example: '/api/vulnerabilities?query=wordpress',
    description: 'Search for CVE vulnerabilities using the NVD API',
    response: {
      query: 'Search query used',
      count: 'Number of vulnerabilities found',
      vulnerabilities: 'Array of vulnerability objects with cveId, description, severity, publishedDate'
    }
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `The endpoint ${req.originalUrl} does not exist`,
    availableEndpoints: ['GET /api/vulnerabilities', 'GET /health', 'GET /']
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: 'Something went wrong on the server',
    timestamp: new Date().toISOString()
  });
});

// Start server
app.listen(PORT, () => {
  console.log('ThreatBoard Vulnerabilities Backend running on port 5000');
  console.log(`Server started at: ${new Date().toISOString()}`);
  console.log(`API endpoint: http://localhost:${PORT}/api/vulnerabilities`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Documentation: http://localhost:${PORT}/`);
  console.log('Features: NVD API integration, clean CVE data, CORS enabled');
});
