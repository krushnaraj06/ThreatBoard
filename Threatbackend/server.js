const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.get('/cves/:tech', async (req, res) => {
  try {
    const { tech } = req.params;
    
    // Fetch CVE data from NVD API
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(tech)}`;
    
    console.log(`Fetching CVEs for technology: ${tech}`);
    
    const response = await axios.get(nvdUrl, {
      headers: {
        'User-Agent': 'ThreatBoard/1.0 (Security Research Tool)'
      },
      timeout: 10000 // 10 second timeout
    });

    // Extract and format the CVE data
    const cveData = response.data.vulnerabilities || [];
    
    // Transform the data to match our frontend expectations
    const formattedCves = cveData.map(cve => {
      const cveItem = cve.cve;
      return {
        id: cveItem.id,
        description: cveItem.descriptions?.[0]?.value || 'No description available',
        severity: cveItem.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || 
                 cveItem.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity || 
                 'Unknown',
        publishedDate: cveItem.published,
        lastModifiedDate: cveItem.lastModified,
        status: cveItem.vulnStatus || 'Unknown'
      };
    });

    console.log(`Found ${formattedCves.length} CVEs for ${tech}`);
    
    res.json(formattedCves);
    
  } catch (error) {
    console.error(`Error fetching CVEs for ${req.params.tech}:`, error.message);
    
    let errorMessage = 'Failed to fetch CVE data';
    let statusCode = 500;
    
    if (error.code === 'ECONNABORTED') {
      errorMessage = 'Request timeout - NVD API is taking too long to respond';
      statusCode = 408;
    } else if (error.response) {
      // NVD API error response
      statusCode = error.response.status;
      if (error.response.status === 404) {
        errorMessage = 'No CVEs found for this technology';
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
      technology: req.params.tech,
      timestamp: new Date().toISOString()
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'ThreatBoard Backend is running',
    timestamp: new Date().toISOString()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'ThreatBoard Backend API',
    version: '1.0.0',
    endpoints: {
      'GET /cves/:tech': 'Fetch CVEs for a specific technology',
      'GET /health': 'Health check endpoint'
    },
    documentation: 'This API fetches CVE data from the National Vulnerability Database (NVD)'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `The endpoint ${req.originalUrl} does not exist`,
    availableEndpoints: ['GET /cves/:tech', 'GET /health', 'GET /']
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
  console.log('Backend running on port 5000');
  console.log(`Server started at: ${new Date().toISOString()}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`CVE endpoint: http://localhost:${PORT}/cves/:tech`);
});
