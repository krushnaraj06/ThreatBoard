# ThreatBoard Backend

A Node.js Express backend API that fetches Common Vulnerabilities and Exposures (CVE) data from the National Vulnerability Database (NVD) API.

## Features

- **Express Server**: Fast, unopinionated web framework for Node.js
- **CORS Enabled**: Cross-origin resource sharing for frontend integration
- **NVD API Integration**: Fetches real-time CVE data from NVD
- **Error Handling**: Comprehensive error handling with proper HTTP status codes
- **Data Transformation**: Formats NVD data for frontend consumption
- **Health Check**: Built-in health monitoring endpoint

## API Endpoints

### GET `/cves/:tech`
Fetches CVE data for a specific technology.

**Parameters:**
- `tech` (string): Technology name to search for (e.g., "React", "Node.js", "MySQL")

**Response Format:**
```json
[
  {
    "id": "CVE-2023-1234",
    "description": "Description of the vulnerability",
    "severity": "High",
    "publishedDate": "2023-01-01T00:00:00Z",
    "lastModifiedDate": "2023-01-15T00:00:00Z",
    "status": "Analyzed"
  }
]
```

**Example Request:**
```bash
GET http://localhost:5000/cves/React
```

### GET `/health`
Health check endpoint to verify the server is running.

**Response:**
```json
{
  "status": "OK",
  "message": "ThreatBoard Backend is running",
  "timestamp": "2023-12-19T10:30:00.000Z"
}
```

### GET `/`
API information and documentation.

## Installation

1. **Navigate to the backend directory:**
   ```bash
   cd Threatbackend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the server:**
   ```bash
   npm start
   ```

   Or for development with auto-restart:
   ```bash
   npm run dev
   ```

## Usage

### Production Mode
```bash
npm start
```

### Development Mode (with nodemon)
```bash
npm run dev
```

The server will start on port 5000 and you'll see:
```
Backend running on port 5000
Server started at: 2023-12-19T10:30:00.000Z
Health check: http://localhost:5000/health
CVE endpoint: http://localhost:5000/cves/:tech
```

## Configuration

### Port
The server runs on port 5000 by default. To change this, modify the `PORT` constant in `server.js`.

### NVD API
The backend integrates with the NVD API v2.0:
- **Base URL**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Search Method**: Keyword search using the `keywordSearch` parameter
- **Rate Limiting**: NVD has rate limits; the backend includes timeout handling

### CORS
CORS is enabled by default to allow frontend integration. The backend accepts requests from any origin.

## Error Handling

The API provides comprehensive error handling:

- **400**: Bad request
- **404**: No CVEs found or endpoint not found
- **408**: Request timeout
- **429**: Rate limit exceeded
- **500**: Internal server error
- **503**: Service unavailable

All errors return JSON responses with:
- Error message
- Technology searched (if applicable)
- Timestamp
- Appropriate HTTP status code

## Data Transformation

The backend transforms NVD API responses to match frontend expectations:

1. **Extracts** relevant CVE information
2. **Normalizes** severity levels (Critical, High, Medium, Low)
3. **Formats** dates for frontend display
4. **Handles** missing or null values gracefully

## Dependencies

- **express**: Web framework
- **cors**: Cross-origin resource sharing
- **axios**: HTTP client for NVD API calls
- **nodemon**: Development dependency for auto-restart

## Development

### Project Structure
```
Threatbackend/
├── package.json          # Dependencies and scripts
├── server.js            # Main server file
└── README.md            # This file
```

### Scripts
- `npm start`: Start production server
- `npm run dev`: Start development server with nodemon

### Logging
The server provides detailed console logging:
- Server startup information
- CVE search requests
- Error details
- Request counts

## Testing

### Manual Testing
Test the API endpoints using curl or a tool like Postman:

```bash
# Health check
curl http://localhost:5000/health

# CVE search
curl http://localhost:5000/cves/React

# API info
curl http://localhost:5000/
```

### Frontend Integration
The backend is designed to work seamlessly with the ThreatBoard React frontend. Ensure both are running:
- Backend: `http://localhost:5000`
- Frontend: `http://localhost:3000`

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the PORT constant in server.js
2. **NVD API errors**: Check internet connection and NVD service status
3. **CORS issues**: Verify CORS middleware is properly configured

### Debug Mode
Enable detailed logging by setting the NODE_ENV environment variable:
```bash
NODE_ENV=development npm start
```

## Security Considerations

- **Input Validation**: Technology names are properly encoded for API calls
- **Rate Limiting**: Built-in timeout handling for NVD API calls
- **Error Exposure**: Error messages don't expose sensitive system information
- **CORS**: Configured for development; restrict origins in production

## Future Enhancements

- [ ] Add authentication and API keys
- [ ] Implement caching for NVD responses
- [ ] Add request rate limiting
- [ ] Include more CVE metadata fields
- [ ] Add filtering and pagination options
- [ ] Implement WebSocket for real-time updates

## License

MIT License - see package.json for details.
