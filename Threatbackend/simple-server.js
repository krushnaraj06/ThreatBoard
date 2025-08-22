const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// CVE endpoint
app.get('/cves/:tech', async (req, res) => {
  try {
    const { tech } = req.params;
    
    // Call NVD API
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${tech}`;
    const response = await axios.get(nvdUrl);
    
    // Return the JSON response directly
    res.json(response.data);
    
  } catch (error) {
    console.error('Error fetching CVE data:', error.message);
    res.status(500).json({ error: "Failed to fetch CVE data" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log('ThreatBoard backend running on port 5000');
});
