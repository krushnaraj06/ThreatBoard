const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting for NVD API calls
const rateLimit = {
  requests: 0,
  resetTime: Date.now() + (5 * 60 * 1000), // 5 minutes
  maxRequests: 4 // Conservative limit to avoid hitting NVD's 5 req/5min limit
};

const checkRateLimit = () => {
  const now = Date.now();
  
  // Reset counter if 5 minutes have passed
  if (now > rateLimit.resetTime) {
    rateLimit.requests = 0;
    rateLimit.resetTime = now + (5 * 60 * 1000);
  }
  
  if (rateLimit.requests >= rateLimit.maxRequests) {
    const waitTime = Math.ceil((rateLimit.resetTime - now) / 1000);
    throw new Error(`Rate limit exceeded. Please wait ${waitTime} seconds before trying again.`);
  }
  
  rateLimit.requests++;
};

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
  try {
    const cve = cveItem.cve;
    
    if (!cve || !cve.id) {
      console.warn('Invalid CVE item structure:', cveItem);
      return null;
    }
    
    return {
      cveId: cve.id,
      description: cve.descriptions?.[0]?.value || 'No description available',
      severity: extractSeverity(cve.metrics),
      publishedDate: formatDate(cve.published)
    };
  } catch (error) {
    console.warn('Error normalizing CVE item:', error);
    return null;
  }
};

// Helper function to sanitize query
const sanitizeQuery = (query) => {
  if (!query) return '';
  
  // Remove special characters that might cause NVD API issues
  let sanitized = query.trim()
    .replace(/[^\w\s\-\.]/g, ' ') // Remove special chars except word chars, spaces, hyphens, dots
    .replace(/\s+/g, ' ') // Replace multiple spaces with single space
    .trim();
  
  // Ensure minimum length
  if (sanitized.length < 2) {
    throw new Error('Query must be at least 2 characters long');
  }
  
  // Limit length to avoid very long queries
  if (sanitized.length > 100) {
    sanitized = sanitized.substring(0, 100);
  }
  
  return sanitized;
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
    
    // Sanitize and validate query
    let sanitizedQuery;
    try {
      sanitizedQuery = sanitizeQuery(query);
    } catch (error) {
      return res.status(400).json({
        error: 'Invalid query',
        message: error.message
      });
    }
    
    // Check rate limit
    try {
      checkRateLimit();
    } catch (error) {
      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: error.message,
        retryAfter: Math.ceil((rateLimit.resetTime - Date.now()) / 1000)
      });
    }
    
    console.log(`Searching for vulnerabilities with query: "${sanitizedQuery}" (original: "${query}")`);
    
    // Build NVD API URL with additional parameters for better results
    const nvdUrl = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
    nvdUrl.searchParams.set('keywordSearch', sanitizedQuery);
    nvdUrl.searchParams.set('resultsPerPage', 20); // Limit results to avoid overwhelming responses
    
    // Call NVD API
    const response = await axios.get(nvdUrl.toString(), {
      headers: {
        'User-Agent': 'ThreatBoard/1.0 (Security Research Tool)',
        'Accept': 'application/json'
      },
      timeout: 20000 // 20 second timeout
    });
    
    // Log response structure for debugging
    console.log(`NVD API response status: ${response.status}`);
    console.log(`NVD API response keys:`, Object.keys(response.data));
    
    // Extract vulnerabilities from response
    const vulnerabilities = response.data.vulnerabilities || [];
    
    if (vulnerabilities.length === 0) {
      console.log(`No vulnerabilities found for query: "${sanitizedQuery}"`);
      return res.json({
        query: sanitizedQuery,
        originalQuery: query,
        count: 0,
        vulnerabilities: [],
        message: 'No vulnerabilities found for the specified query',
        suggestions: [
          'Try a different search term',
          'Check spelling',
          'Use more general terms',
          'Try technology names (e.g., "apache", "wordpress", "mysql")'
        ]
      });
    }
    
    // Normalize and clean the data, filter out invalid items
    const cleanedVulnerabilities = vulnerabilities
      .map(normalizeCVE)
      .filter(item => item !== null); // Remove any null items
    
    if (cleanedVulnerabilities.length === 0) {
      console.log(`All vulnerabilities were invalid for query: "${sanitizedQuery}"`);
      return res.json({
        query: sanitizedQuery,
        originalQuery: query,
        count: 0,
        vulnerabilities: [],
        message: 'Found vulnerabilities but failed to process them',
        rawCount: vulnerabilities.length
      });
    }
    
    console.log(`Found ${cleanedVulnerabilities.length} valid vulnerabilities for query: "${sanitizedQuery}" (raw: ${vulnerabilities.length})`);
    
    // Send clean response
    res.json({
      query: sanitizedQuery,
      originalQuery: query,
      count: cleanedVulnerabilities.length,
      vulnerabilities: cleanedVulnerabilities,
      rateLimit: {
        requestsUsed: rateLimit.requests,
        requestsRemaining: rateLimit.maxRequests - rateLimit.requests,
        resetTime: new Date(rateLimit.resetTime).toISOString()
      }
    });
    
  } catch (error) {
    console.error('Error fetching vulnerabilities:', error.message);
    
    let errorMessage = 'Failed to fetch vulnerability data';
    let statusCode = 500;
    let details = {};
    
    if (error.code === 'ECONNABORTED') {
      errorMessage = 'Request timeout - NVD API is taking too long to respond';
      statusCode = 408;
      details = { suggestion: 'Try again in a few minutes' };
    } else if (error.response) {
      statusCode = error.response.status;
      if (error.response.status === 404) {
        errorMessage = 'No vulnerabilities found for the specified query';
        statusCode = 200; // Return 200 with empty array instead of 404
        return res.json({
          query: req.query.query || 'unknown',
          count: 0,
          vulnerabilities: [],
          message: errorMessage
        });
      } else if (error.response.status === 429) {
        errorMessage = 'NVD API rate limit exceeded - please try again later';
        statusCode = 429;
        details = { 
          suggestion: 'Wait a few minutes before trying again',
          retryAfter: '5 minutes'
        };
      } else {
        errorMessage = `NVD API error: ${error.response.status}`;
        details = { 
          status: error.response.status,
          suggestion: 'Try again later or contact support'
        };
      }
    } else if (error.request) {
      errorMessage = 'No response from NVD API - please check your internet connection';
      statusCode = 503;
      details = { suggestion: 'Check your internet connection and try again' };
    }
    
    res.status(statusCode).json({
      error: errorMessage,
      query: req.query.query || 'unknown',
      timestamp: new Date().toISOString(),
      details,
      rateLimit: {
        requestsUsed: rateLimit.requests,
        requestsRemaining: rateLimit.maxRequests - rateLimit.requests,
        resetTime: new Date(rateLimit.resetTime).toISOString()
      }
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'ThreatBoard Robust Vulnerabilities Backend is running',
    timestamp: new Date().toISOString(),
    endpoint: '/api/vulnerabilities',
    rateLimit: {
      requestsUsed: rateLimit.requests,
      requestsRemaining: rateLimit.maxRequests - rateLimit.requests,
      resetTime: new Date(rateLimit.resetTime).toISOString()
    }
  });
});

// Root endpoint with API info
app.get('/', (req, res) => {
  res.json({
    message: 'ThreatBoard Robust Vulnerabilities API',
    version: '1.1.0',
    endpoint: 'GET /api/vulnerabilities?query={search_term}',
    example: '/api/vulnerabilities?query=wordpress',
    description: 'Search for CVE vulnerabilities using the NVD API with improved reliability',
    features: [
      'Rate limiting protection',
      'Query sanitization',
      'Better error handling',
      'Response validation',
      'Debugging information'
    ],
    response: {
      query: 'Sanitized search query used',
      originalQuery: 'Original query provided by user',
      count: 'Number of valid vulnerabilities found',
      vulnerabilities: 'Array of vulnerability objects with cveId, description, severity, publishedDate',
      rateLimit: 'Current rate limit status'
    },
    tips: [
      'Use technology names for best results (e.g., "wordpress", "apache", "mysql")',
      'Avoid special characters in queries',
      'Wait 5 minutes between requests if you hit rate limits',
      'Check the health endpoint for rate limit status'
    ]
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
  console.log('ThreatBoard Robust Vulnerabilities Backend running on port 5000');
  console.log(`Server started at: ${new Date().toISOString()}`);
  console.log(`API endpoint: http://localhost:${PORT}/api/vulnerabilities`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Documentation: http://localhost:${PORT}/`);
  console.log('Features: NVD API integration, rate limiting, query sanitization, robust error handling');
  console.log('Rate limit: 4 requests per 5 minutes (conservative to avoid NVD limits)');
});
