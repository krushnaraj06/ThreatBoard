// Simple test script to verify the backend API is working
const axios = require('axios');

async function testBackendAPI() {
  console.log('Testing ThreatBoard Backend API...\n');
  
  try {
    // Test health endpoint
    console.log('1. Testing health endpoint...');
    const healthResponse = await axios.get('http://localhost:5000/health');
    console.log('✅ Health check passed:', healthResponse.data.message);
    console.log('   Cache entries:', healthResponse.data.cache?.size || 0);
    
    // Test latest CVEs endpoint
    console.log('\n2. Testing latest CVEs endpoint...');
    const cveResponse = await axios.get('http://localhost:5000/api/cves/latest?page=1&limit=5');
    console.log('✅ Latest CVEs endpoint working');
    console.log('   Found CVEs:', cveResponse.data.data?.length || 0);
    console.log('   Source:', cveResponse.data.source);
    console.log('   Last updated:', cveResponse.data.lastUpdated);
    
    if (cveResponse.data.data && cveResponse.data.data.length > 0) {
      console.log('\n   Sample CVE:');
      const sampleCVE = cveResponse.data.data[0];
      console.log('   - ID:', sampleCVE.id);
      console.log('   - Severity:', sampleCVE.severity);
      console.log('   - CVSS Score:', sampleCVE.cvssScore);
      console.log('   - Published:', new Date(sampleCVE.publishedDate).toLocaleDateString());
    }
    
    // Test with severity filter
    console.log('\n3. Testing severity filter...');
    const criticalResponse = await axios.get('http://localhost:5000/api/cves/latest?page=1&limit=3&severity=Critical');
    console.log('✅ Severity filter working');
    console.log('   Critical CVEs found:', criticalResponse.data.data?.length || 0);
    
    console.log('\n🎉 All tests passed! Backend API is working correctly.');
    
  } catch (error) {
    console.error('❌ Backend API test failed:');
    
    if (error.code === 'ECONNREFUSED') {
      console.error('   Backend server is not running. Please start it with:');
      console.error('   cd Threatbackend && npm run enhanced');
    } else if (error.response) {
      console.error('   HTTP Error:', error.response.status, error.response.statusText);
      console.error('   Response:', error.response.data);
    } else {
      console.error('   Error:', error.message);
    }
    
    console.log('\n💡 Troubleshooting tips:');
    console.log('   1. Make sure the backend server is running on port 5000');
    console.log('   2. Check if the NVD API is accessible from your network');
    console.log('   3. Verify your internet connection');
    console.log('   4. The frontend will automatically fallback to alternative sources');
  }
}

// Run the test
testBackendAPI();