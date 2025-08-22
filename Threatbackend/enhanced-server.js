const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Simple in-memory cache (in production, use Redis or similar)
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Helper function to map CVSS score to severity
const mapCVSSScoreToSeverity = (cvssScore) => {
  if (!cvssScore || cvssScore === 0) return 'Unknown';
  
  if (cvssScore >= 9.0) return 'Critical';
  if (cvssScore >= 7.0) return 'High';
  if (cvssScore >= 4.0) return 'Medium';
  if (cvssScore >= 0.1) return 'Low';
  
  return 'Unknown';
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

// Helper function to normalize CVE data
const normalizeCVEData = (cveItem) => {
  const cve = cveItem.cve;
  
  // Extract CVSS score from metrics
  let cvssScore = 0;
  let severity = 'Unknown';
  
  if (cve.metrics) {
    // Try CVSS v3.1 first, then v3.0, then v2
    if (cve.metrics.cvssMetricV31 && cve.metrics.cvssMetricV31[0]) {
      cvssScore = cve.metrics.cvssMetricV31[0].cvssData.baseScore || 0;
      severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity || 'Unknown';
    } else if (cve.metrics.cvssMetricV30 && cve.metrics.cvssMetricV30[0]) {
      cvssScore = cve.metrics.cvssMetricV30[0].cvssData.baseScore || 0;
      severity = cve.metrics.cvssMetricV30[0].cvssData.baseSeverity || 'Unknown';
    } else if (cve.metrics.cvssMetricV2 && cve.metrics.cvssMetricV2[0]) {
      cvssScore = cve.metrics.cvssMetricV2[0].cvssData.baseScore || 0;
      // Map CVSS v2 score to severity
      severity = mapCVSSScoreToSeverity(cvssScore);
    }
  }
  
  // Normalize severity to our standard format
  if (severity === 'Unknown' && cvssScore > 0) {
    severity = mapCVSSScoreToSeverity(cvssScore);
  }
  
  return {
    cveId: cve.id,
    description: cve.descriptions?.[0]?.value || 'No description available',
    severity: severity,
    cvssScore: cvssScore,
    publishedDate: formatDate(cve.published),
    lastModifiedDate: formatDate(cve.lastModified),
    status: cve.vulnStatus || 'Unknown',
    // Extract technology from description or keywords
    technology: extractTechnologyFromDescription(cve.descriptions?.[0]?.value || ''),
    // Additional metadata
    references: cve.references?.map(ref => ref.url) || [],
    configurations: cve.configurations || []
  };
};

// Helper function to extract technology from description
const extractTechnologyFromDescription = (description) => {
  if (!description) return 'Unknown';
  
  const commonTechs = [
    'Apache', 'Nginx', 'WordPress', 'Drupal', 'Joomla', 'Magento',
    'React', 'Angular', 'Vue', 'Node.js', 'Express', 'Django',
    'Laravel', 'Spring', 'MySQL', 'PostgreSQL', 'MongoDB', 'Redis',
    'Docker', 'Kubernetes', 'AWS', 'Azure', 'GCP', 'Linux', 'Windows'
  ];
  
  const lowerDesc = description.toLowerCase();
  for (const tech of commonTechs) {
    if (lowerDesc.includes(tech.toLowerCase())) {
      return tech;
    }
  }
  
  return 'Unknown';
};

// Helper function to build NVD API URL with parameters
const buildNVDUrl = (params) => {
  const baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  const queryParams = new URLSearchParams();
  
  // Add keyword search if provided
  if (params.keyword) {
    queryParams.append('keywordSearch', params.keyword);
  }
  
  // Add date range if year is specified
  if (params.year) {
    const startDate = `${params.year}-01-01T00:00:00:000 UTC-05:00`;
    const endDate = `${params.year}-12-31T23:59:59:000 UTC-05:00`;
    queryParams.append('pubStartDate', startDate);
    queryParams.append('pubEndDate', endDate);
  }
  
  // Add results per page (NVD API limit is 2000)
  queryParams.append('resultsPerPage', 2000);
  
  return `${baseUrl}?${queryParams.toString()}`;
};

// Helper function to filter data based on query parameters
const filterCVEData = (data, params) => {
  let filtered = [...data];
  
  // Filter by severity
  if (params.severity && params.severity !== 'all') {
    filtered = filtered.filter(cve => 
      cve.severity.toLowerCase() === params.severity.toLowerCase()
    );
  }
  
  // Filter by year
  if (params.year) {
    filtered = filtered.filter(cve => {
      const cveYear = new Date(cve.publishedDate).getFullYear();
      return cveYear.toString() === params.year;
    });
  }
  
  // Filter by keyword (search in description and technology)
  if (params.keyword) {
    const keyword = params.keyword.toLowerCase();
    filtered = filtered.filter(cve => 
      cve.description.toLowerCase().includes(keyword) ||
      cve.technology.toLowerCase().includes(keyword) ||
      cve.cveId.toLowerCase().includes(keyword)
    );
  }
  
  return filtered;
};

// Helper function to apply pagination
const applyPagination = (data, page = 1, limit = 20) => {
  const pageNum = parseInt(page) || 1;
  const limitNum = parseInt(limit) || 20;
  
  const startIndex = (pageNum - 1) * limitNum;
  const endIndex = startIndex + limitNum;
  
  return {
    data: data.slice(startIndex, endIndex),
    pagination: {
      page: pageNum,
      limit: limitNum,
      total: data.length,
      totalPages: Math.ceil(data.length / limitNum),
      hasNext: endIndex < data.length,
      hasPrev: pageNum > 1
    }
  };
};

// Latest CVEs endpoint for news feed
app.get('/api/cves/latest', async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      severity
    } = req.query;
    
    // Create cache key
    const cacheKey = `latest-cves:${page}:${limit}:${severity || 'all'}`;
    
    // Check cache first
    const cached = cache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
      console.log(`Serving latest CVEs from cache: ${cacheKey}`);
      return res.json(cached.data);
    }
    
    console.log(`Fetching latest CVEs from NVD API: page ${page}`);
    
    // Calculate date range for recent CVEs (last 30 days)
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    
    // Build NVD API URL for latest CVEs
    const nvdUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    const queryParams = new URLSearchParams({
      resultsPerPage: Math.min(parseInt(limit), 100),
      startIndex: (parseInt(page) - 1) * parseInt(limit),
      pubStartDate: startDate.toISOString(),
      pubEndDate: endDate.toISOString()
    });
    
    // Fetch data from NVD API
    const response = await axios.get(`${nvdUrl}?${queryParams.toString()}`, {
      headers: {
        'User-Agent': 'ThreatBoard/2.0 (Vulnerability Management System)'
      },
      timeout: 15000
    });
    
    // Extract and normalize CVE data
    const rawCVEs = response.data.vulnerabilities || [];
    let normalizedCVEs = rawCVEs.map(vuln => {
      const cve = vuln.cve;
      const metrics = cve.metrics;
      
      let cvssScore = 0;
      let severity = 'Unknown';
      let attackVector = 'Unknown';
      let complexity = 'Unknown';
      let privilegesRequired = 'Unknown';
      let userInteraction = 'Unknown';
      let scope = 'Unknown';

      // Extract CVSS data (prefer v3.1, then v3.0, then v2)
      if (metrics?.cvssMetricV31?.[0]) {
        const cvss = metrics.cvssMetricV31[0].cvssData;
        cvssScore = cvss.baseScore;
        severity = cvss.baseSeverity;
        attackVector = cvss.attackVector;
        complexity = cvss.attackComplexity;
        privilegesRequired = cvss.privilegesRequired;
        userInteraction = cvss.userInteraction;
        scope = cvss.scope;
      } else if (metrics?.cvssMetricV30?.[0]) {
        const cvss = metrics.cvssMetricV30[0].cvssData;
        cvssScore = cvss.baseScore;
        severity = cvss.baseSeverity;
        attackVector = cvss.attackVector;
        complexity = cvss.attackComplexity;
        privilegesRequired = cvss.privilegesRequired;
        userInteraction = cvss.userInteraction;
        scope = cvss.scope;
      } else if (metrics?.cvssMetricV2?.[0]) {
        cvssScore = metrics.cvssMetricV2[0].cvssData.baseScore;
        severity = mapCVSSScoreToSeverity(cvssScore);
        attackVector = 'Network'; // Default for v2
        complexity = 'Low';
        privilegesRequired = 'None';
        userInteraction = 'None';
        scope = 'Unchanged';
      }

      return {
        id: cve.id,
        description: cve.descriptions?.[0]?.value || 'No description available',
        cvssScore: cvssScore,
        severity: severity,
        publishedDate: cve.published,
        lastModifiedDate: cve.lastModified,
        attackVector: attackVector,
        complexity: complexity,
        privilegesRequired: privilegesRequired,
        userInteraction: userInteraction,
        scope: scope,
        references: cve.references?.map(ref => ref.url) || [],
        status: cve.vulnStatus || 'Unknown'
      };
    });
    
    // Apply severity filter if specified
    if (severity && severity !== 'all') {
      normalizedCVEs = normalizedCVEs.filter(cve => 
        cve.severity.toLowerCase() === severity.toLowerCase()
      );
    }
    
    // Sort by published date (newest first)
    normalizedCVEs.sort((a, b) => new Date(b.publishedDate) - new Date(a.publishedDate));
    
    const result = {
      data: normalizedCVEs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: response.data.totalResults || normalizedCVEs.length,
        hasMore: normalizedCVEs.length === parseInt(limit)
      },
      source: 'NVD API',
      lastUpdated: new Date().toISOString()
    };
    
    // Cache the results
    cache.set(cacheKey, {
      data: result,
      timestamp: Date.now()
    });
    
    console.log(`Found ${normalizedCVEs.length} latest CVEs for page ${page}`);
    
    res.json(result);
    
  } catch (error) {
    console.error('Error fetching latest CVEs:', error.message);
    
    let errorMessage = 'Failed to fetch latest CVE data';
    let statusCode = 500;
    
    if (error.code === 'ECONNABORTED') {
      errorMessage = 'Request timeout - NVD API is taking too long to respond';
      statusCode = 408;
    } else if (error.response) {
      statusCode = error.response.status;
      if (error.response.status === 404) {
        errorMessage = 'No recent CVEs found';
      } else if (error.response.status === 429) {
        errorMessage = 'Rate limit exceeded - please try again later';
      } else {
        errorMessage = `NVD API error: ${error.response.status}`;
      }
    } else if (error.request) {
      errorMessage = 'No response from NVD API - please check your internet connection';
      statusCode = 503;
    }
    
    res.status(statusCode).json({
      error: errorMessage,
      query: req.query,
      timestamp: new Date().toISOString(),
      fallback: 'Consider using cached data or alternative sources'
    });
  }
});

// Main CVE endpoint
app.get('/api/cves', async (req, res) => {
  try {
    const {
      severity,
      year,
      keyword,
      page = 1,
      limit = 20
    } = req.query;
    
    // Create cache key based on query parameters
    const cacheKey = `cves:${severity || 'all'}:${year || 'all'}:${keyword || 'all'}`;
    
    // Check cache first
    const cached = cache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
      console.log(`Serving from cache: ${cacheKey}`);
      const paginatedResult = applyPagination(cached.data, page, limit);
      return res.json(paginatedResult);
    }
    
    console.log(`Fetching from NVD API: ${cacheKey}`);
    
    // Build NVD API URL
    const nvdUrl = buildNVDUrl({ year, keyword });
    
    // Fetch data from NVD API
    const response = await axios.get(nvdUrl, {
      headers: {
        'User-Agent': 'ThreatBoard/1.0 (Security Research Tool)'
      },
      timeout: 15000 // 15 second timeout
    });
    
    // Extract and normalize CVE data
    const rawCVEs = response.data.vulnerabilities || [];
    const normalizedCVEs = rawCVEs.map(normalizeCVEData);
    
    // Apply filters
    const filteredCVEs = filterCVEData(normalizedCVEs, { severity, year, keyword });
    
    // Cache the filtered results
    cache.set(cacheKey, {
      data: filteredCVEs,
      timestamp: Date.now()
    });
    
    // Apply pagination
    const result = applyPagination(filteredCVEs, page, limit);
    
    console.log(`Found ${filteredCVEs.length} CVEs, returning ${result.data.length} for page ${page}`);
    
    res.json(result);
    
  } catch (error) {
    console.error('Error fetching CVE data:', error.message);
    
    let errorMessage = 'Failed to fetch CVE data';
    let statusCode = 500;
    
    if (error.code === 'ECONNABORTED') {
      errorMessage = 'Request timeout - NVD API is taking too long to respond';
      statusCode = 408;
    } else if (error.response) {
      statusCode = error.response.status;
      if (error.response.status === 404) {
        errorMessage = 'No CVEs found for the specified criteria';
      } else if (error.response.status === 429) {
        errorMessage = 'Rate limit exceeded - please try again later';
      } else {
        errorMessage = `NVD API error: ${error.response.status}`;
      }
    } else if (error.request) {
      errorMessage = 'No response from NVD API - please check your internet connection';
      statusCode = 503;
    }
    
    res.status(statusCode).json({
      error: errorMessage,
      query: req.query,
      timestamp: new Date().toISOString()
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'ThreatBoard Enhanced Backend is running',
    timestamp: new Date().toISOString(),
    cache: {
      size: cache.size,
      entries: Array.from(cache.keys())
    }
  });
});

// API documentation endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'ThreatBoard Enhanced Backend API',
    version: '2.0.0',
    endpoints: {
      'GET /api/cves': 'Fetch normalized CVE data with filtering and pagination',
      'GET /health': 'Health check endpoint'
    },
    queryParameters: {
      'severity': 'Filter by severity (Critical, High, Medium, Low, Unknown)',
      'year': 'Filter by publication year (e.g., 2023)',
      'keyword': 'Search in description, technology, or CVE ID',
      'page': 'Page number for pagination (default: 1)',
      'limit': 'Items per page (default: 20, max: 100)'
    },
    examples: [
      '/api/cves?severity=HIGH&year=2023&keyword=apache&page=1&limit=20',
      '/api/cves?severity=Critical&limit=50',
      '/api/cves?keyword=wordpress&year=2022'
    ],
    features: [
      'NVD API integration',
      'Data normalization and cleaning',
      'Advanced filtering',
      'Pagination support',
      'In-memory caching',
      'CVSS score mapping',
      'Date formatting',
      'Technology extraction'
    ]
  });
});

// Clear cache endpoint (for development/testing)
app.delete('/cache', (req, res) => {
  const cacheSize = cache.size;
  cache.clear();
  res.json({
    message: 'Cache cleared successfully',
    clearedEntries: cacheSize,
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `The endpoint ${req.originalUrl} does not exist`,
    availableEndpoints: ['GET /api/cves', 'GET /health', 'GET /', 'DELETE /cache']
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
  console.log('ThreatBoard Enhanced Backend running on port 5000');
  console.log(`Server started at: ${new Date().toISOString()}`);
  console.log(`API endpoint: http://localhost:${PORT}/api/cves`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Documentation: http://localhost:${PORT}/`);
  console.log('Features: NVD API integration, data normalization, filtering, pagination, caching');
});
