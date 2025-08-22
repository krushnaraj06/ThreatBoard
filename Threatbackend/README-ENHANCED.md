# ThreatBoard Enhanced Backend

A production-ready Node.js + Express backend that connects to the NVD API and provides cleaned, normalized CVE data for the ThreatBoard frontend dashboard.

## ✨ **Features**

### 🔌 **NVD API Integration**
- **Real-time Data**: Fetches live CVE data from National Vulnerability Database
- **Smart Caching**: In-memory cache with 5-minute TTL for performance
- **Rate Limit Handling**: Built-in protection against NVD API limits
- **Error Recovery**: Graceful fallbacks and comprehensive error handling

### 🧹 **Data Normalization & Cleaning**
- **CVSS Score Mapping**: Automatically maps CVSS scores to severity levels
- **Date Formatting**: Converts ISO dates to DD/MM/YYYY format
- **Technology Extraction**: Automatically identifies technologies from descriptions
- **Data Standardization**: Consistent output format for frontend consumption

### 🔍 **Advanced Filtering & Search**
- **Severity Filtering**: Filter by Critical, High, Medium, Low, Unknown
- **Year Filtering**: Filter by publication year
- **Keyword Search**: Search across CVE ID, description, and technology
- **Combined Filters**: Use multiple filters simultaneously

### 📄 **Pagination Support**
- **Configurable Limits**: Set items per page (default: 20, max: 100)
- **Page Navigation**: Easy page-by-page browsing
- **Metadata**: Total count, total pages, next/previous indicators

### 🚀 **Performance Features**
- **Intelligent Caching**: Cache results based on query parameters
- **Efficient Filtering**: Server-side filtering for large datasets
- **Optimized Queries**: Smart NVD API URL building
- **Memory Management**: Automatic cache cleanup

## 🚀 **Quick Start**

### 1. **Install Dependencies**
```bash
cd Threatbackend
npm install
```

### 2. **Start Enhanced Server**
```bash
npm run enhanced
```

### 3. **Test the API**
```bash
curl http://localhost:5000/health
```

## 📡 **API Endpoints**

### **GET `/api/cves`** - Main CVE Endpoint

**Query Parameters:**
- `severity` (optional): Filter by severity level
- `year` (optional): Filter by publication year
- `keyword` (optional): Search keyword
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 20)

**Example Requests:**
```bash
# Get all CVEs (paginated)
GET /api/cves

# Filter by severity
GET /api/cves?severity=HIGH

# Filter by year
GET /api/cves?year=2023

# Search by keyword
GET /api/cves?keyword=apache

# Combined filters with pagination
GET /api/cves?severity=HIGH&year=2023&keyword=apache&page=1&limit=50
```

**Response Format:**
```json
{
  "data": [
    {
      "cveId": "CVE-2023-1234",
      "description": "Vulnerability description...",
      "severity": "High",
      "cvssScore": 7.5,
      "publishedDate": "15/01/2023",
      "lastModifiedDate": "20/01/2023",
      "status": "Analyzed",
      "technology": "Apache",
      "references": ["https://example.com"],
      "configurations": []
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 150,
    "totalPages": 8,
    "hasNext": true,
    "hasPrev": false
  }
}
```

### **GET `/health`** - Health Check
```json
{
  "status": "OK",
  "message": "ThreatBoard Enhanced Backend is running",
  "timestamp": "2023-12-19T10:30:00.000Z",
  "cache": {
    "size": 5,
    "entries": ["cves:all:all:all", "cves:HIGH:2023:all"]
  }
}
```

### **GET `/`** - API Documentation
Returns comprehensive API documentation with examples and feature list.

### **DELETE `/cache`** - Clear Cache
Clears all cached data (useful for development/testing).

## 🔧 **Configuration**

### **Environment Variables**
```bash
# Port configuration
PORT=5000

# Cache TTL (in milliseconds)
CACHE_TTL=300000
```

### **NVD API Settings**
- **Base URL**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Rate Limits**: Built-in handling for NVD API limits
- **Timeout**: 15 seconds for API calls
- **User Agent**: `ThreatBoard/1.0 (Security Research Tool)`

## 📊 **Data Processing Pipeline**

### 1. **NVD API Fetch**
- Builds optimized query URLs
- Handles rate limiting and timeouts
- Fetches up to 2000 results per request

### 2. **Data Normalization**
- Extracts CVSS scores from multiple versions (v3.1, v3.0, v2)
- Maps scores to standardized severity levels
- Formats dates to DD/MM/YYYY
- Extracts technology information

### 3. **Filtering & Search**
- Applies server-side filters
- Performs keyword search across multiple fields
- Combines multiple filter criteria

### 4. **Pagination**
- Calculates page boundaries
- Provides navigation metadata
- Optimizes for frontend consumption

### 5. **Caching**
- Creates cache keys based on query parameters
- Stores filtered results for 5 minutes
- Reduces NVD API calls

## 🎯 **Use Cases**

### **Security Teams**
- Monitor high-severity vulnerabilities
- Track vulnerabilities by technology stack
- Generate vulnerability reports

### **Developers**
- Check dependencies for known vulnerabilities
- Monitor security updates
- Integrate security scanning

### **DevOps Engineers**
- Monitor infrastructure vulnerabilities
- Track security patch requirements
- Generate compliance reports

## 🔒 **Security Features**

- **Input Validation**: All query parameters are validated
- **Rate Limiting**: Built-in protection against abuse
- **Error Handling**: No sensitive information in error messages
- **CORS**: Properly configured for frontend integration

## 📈 **Performance Optimization**

### **Caching Strategy**
- **Query-based Keys**: Cache key includes all filter parameters
- **TTL Management**: 5-minute cache lifetime
- **Memory Efficiency**: Automatic cache cleanup

### **Filtering Optimization**
- **Server-side Processing**: Reduces frontend load
- **Efficient Algorithms**: Optimized for large datasets
- **Smart Queries**: Minimizes NVD API calls

## 🧪 **Testing**

### **Manual Testing**
```bash
# Test basic endpoint
curl "http://localhost:5000/api/cves"

# Test filtering
curl "http://localhost:5000/api/cves?severity=HIGH&limit=5"

# Test pagination
curl "http://localhost:5000/api/cves?page=2&limit=10"

# Test search
curl "http://localhost:5000/api/cves?keyword=wordpress&year=2023"
```

### **Load Testing**
```bash
# Test with multiple concurrent requests
ab -n 100 -c 10 "http://localhost:5000/api/cves?severity=HIGH"
```

## 🚀 **Deployment**

### **Production Considerations**
- **Redis Cache**: Replace in-memory cache with Redis
- **Load Balancing**: Use multiple instances behind a load balancer
- **Monitoring**: Add health checks and metrics
- **Logging**: Implement structured logging

### **Docker Support**
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 5000
CMD ["npm", "run", "enhanced"]
```

## 🔮 **Future Enhancements**

- [ ] **Redis Integration**: Replace in-memory cache
- [ ] **WebSocket Support**: Real-time vulnerability updates
- [ ] **Advanced Analytics**: Vulnerability trend analysis
- [ ] **Export Functionality**: CSV, JSON, PDF export
- [ ] **User Authentication**: API key management
- [ ] **Rate Limiting**: Per-user request limits
- [ ] **Metrics Dashboard**: Performance monitoring

## 🐛 **Troubleshooting**

### **Common Issues**

1. **NVD API Timeouts**
   - Check internet connection
   - Verify NVD service status
   - Increase timeout if needed

2. **Cache Memory Issues**
   - Monitor memory usage
   - Adjust cache TTL
   - Implement cache size limits

3. **Filter Performance**
   - Use specific filters to reduce data
   - Implement query optimization
   - Add database indexing if needed

### **Debug Mode**
```bash
# Enable detailed logging
DEBUG=* npm run enhanced

# Monitor cache performance
curl http://localhost:5000/health
```

## 📚 **API Examples**

### **Frontend Integration**
```javascript
// Fetch high-severity vulnerabilities from 2023
const fetchHighSeverityCVEs = async () => {
  try {
    const response = await fetch('/api/cves?severity=HIGH&year=2023&limit=50');
    const data = await response.json();
    
    console.log(`Found ${data.pagination.total} vulnerabilities`);
    return data.data;
  } catch (error) {
    console.error('Failed to fetch CVEs:', error);
  }
};

// Search for specific technology
const searchTechnology = async (keyword) => {
  const response = await fetch(`/api/cves?keyword=${encodeURIComponent(keyword)}`);
  return response.json();
};
```

### **Pagination Implementation**
```javascript
const fetchPage = async (page, limit = 20) => {
  const response = await fetch(`/api/cves?page=${page}&limit=${limit}`);
  const data = await response.json();
  
  // Navigation logic
  if (data.pagination.hasNext) {
    // Show next button
  }
  if (data.pagination.hasPrev) {
    // Show previous button
  }
  
  return data;
};
```

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests and documentation
5. Submit a pull request

## 📄 **License**

MIT License - see package.json for details.

---

**Built with ❤️ for the security community**

*This backend provides enterprise-grade CVE data processing with performance, reliability, and ease of use in mind.*
