// Test script to verify XML parsing is working correctly
const fs = require('fs');
const path = require('path');

// Mock DOM parser for Node.js environment
const { JSDOM } = require('jsdom');
global.DOMParser = new JSDOM().window.DOMParser;

// Import the parser functions
const { parseUniversalScanner, detectScannerType } = require('./src/utils/scannerParsers.js');

async function testXMLParsing() {
  console.log('Testing XML parsing for complex Nessus file...\n');
  
  try {
    // Read the complex XML file
    const xmlPath = path.join(__dirname, 'test-data', 'nessus-complex-export.xml');
    const xmlContent = fs.readFileSync(xmlPath, 'utf8');
    
    console.log('1. File loaded successfully');
    console.log('   File size:', xmlContent.length, 'characters');
    
    // Detect scanner type
    const scannerType = detectScannerType(xmlContent, 'nessus-complex-export.xml');
    console.log('2. Scanner type detected:', scannerType);
    
    // Parse the vulnerabilities
    const vulnerabilities = parseUniversalScanner(xmlContent, 'nessus-complex-export.xml', 'xml');
    
    console.log('3. Parsing completed successfully');
    console.log('   Total vulnerabilities found:', vulnerabilities.length);
    
    if (vulnerabilities.length > 0) {
      console.log('\n4. Sample vulnerabilities:');
      vulnerabilities.slice(0, 5).forEach((vuln, index) => {
        console.log(`   ${index + 1}. ${vuln.cveId} - ${vuln.title}`);
        console.log(`      Severity: ${vuln.severity}, Asset: ${vuln.asset}`);
        console.log(`      Exploit Available: ${vuln.exploitAvailable}`);
        console.log(`      CVSS Score: ${vuln.cvssScore}`);
        console.log('');
      });
      
      // Check severity distribution
      const severityCount = vulnerabilities.reduce((acc, vuln) => {
        acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
        return acc;
      }, {});
      
      console.log('5. Severity distribution:');
      Object.entries(severityCount).forEach(([severity, count]) => {
        console.log(`   ${severity}: ${count}`);
      });
      
      // Check for high-priority vulnerabilities
      const criticalVulns = vulnerabilities.filter(v => v.severity === 'Critical');
      const highVulns = vulnerabilities.filter(v => v.severity === 'High');
      const exploitableVulns = vulnerabilities.filter(v => v.exploitAvailable);
      
      console.log('\n6. Priority analysis:');
      console.log(`   Critical vulnerabilities: ${criticalVulns.length}`);
      console.log(`   High vulnerabilities: ${highVulns.length}`);
      console.log(`   Exploitable vulnerabilities: ${exploitableVulns.length}`);
      
      if (criticalVulns.length > 0) {
        console.log('\n   Critical vulnerabilities:');
        criticalVulns.forEach(vuln => {
          console.log(`   - ${vuln.cveId}: ${vuln.title} (${vuln.asset})`);
        });
      }
      
      console.log('\n✅ XML parsing test completed successfully!');
      console.log('   The vulnerabilities should now appear sorted by priority in the UI.');
      
    } else {
      console.log('❌ No vulnerabilities found - there may be a parsing issue');
    }
    
  } catch (error) {
    console.error('❌ XML parsing test failed:');
    console.error('   Error:', error.message);
    console.error('   Stack:', error.stack);
    
    console.log('\n💡 Troubleshooting tips:');
    console.log('   1. Make sure the XML file exists and is valid');
    console.log('   2. Check if jsdom is installed: npm install jsdom');
    console.log('   3. Verify the XML structure matches Nessus format');
  }
}

// Run the test
testXMLParsing();