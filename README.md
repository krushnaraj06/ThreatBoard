# ThreatBoard - Vulnerability Dashboard

A modern React-based dashboard for searching and displaying Common Vulnerabilities and Exposures (CVEs) related to specific technologies, frameworks, and software.

## Features

- **Clean Dashboard Layout**: Modern, responsive design with Tailwind CSS
- **Technology Search**: Search for CVEs by technology name (React, Node.js, MySQL, WordPress, etc.)
- **Real-time Results**: Fetches data from backend API and displays in styled table
- **Interactive Elements**: Clickable CVE IDs that link to NVD database
- **State Management**: Loading states, error handling, and empty results handling
- **Download Report**: UI button for future report generation feature
- **Responsive Design**: Works on desktop and mobile devices

## Tech Stack

- **Frontend**: React 18 with functional components and hooks
- **Styling**: Tailwind CSS for modern, responsive design
- **HTTP Client**: Built-in fetch API (no external dependencies)
- **Build Tool**: Create React App

## Prerequisites

- Node.js (version 14 or higher)
- npm or yarn package manager
- Backend server running at `http://localhost:5000` (for CVE data)

## Installation

1. **Clone or download the project files**

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start the development server**:
   ```bash
   npm start
   ```

4. **Open your browser** and navigate to `http://localhost:3000`

## Usage

1. **Enter a technology name** in the search field (e.g., "React", "Node.js", "MySQL")
2. **Click "Search CVEs"** to fetch vulnerability data
3. **View results** in the styled table below
4. **Click on CVE IDs** to open detailed information in the NVD database
5. **Use "Download Report"** button for future report generation

## API Integration

The application expects a backend API at `http://localhost:5000/cves/:tech` that returns CVE data in the following format:

```json
[
  {
    "id": "CVE-2023-1234",
    "description": "Description of the vulnerability",
    "severity": "High",
    "publishedDate": "2023-01-01T00:00:00Z"
  }
]
```

## Project Structure

```
src/
├── components/
│   ├── ThreatBoard.js      # Main dashboard component
│   ├── SearchForm.js       # Search input and button
│   ├── ResultsTable.js     # CVE results table
│   ├── LoadingSpinner.js   # Loading animation
│   └── ErrorMessage.js     # Error display component
├── App.js                  # Main app component
├── index.js               # Application entry point
└── index.css              # Global styles and Tailwind imports
```

## Available Scripts

- `npm start` - Start development server
- `npm build` - Build for production
- `npm test` - Run tests
- `npm eject` - Eject from Create React App (irreversible)

## Customization

### Styling
- Modify `tailwind.config.js` to customize colors, spacing, and other design tokens
- Update component classes in individual component files
- Add custom CSS in `src/index.css`

### API Endpoint
- Change the API URL in `src/components/ThreatBoard.js` line 25
- Update error messages in `src/components/ErrorMessage.js` if needed

### Data Fields
- Modify `src/components/ResultsTable.js` to display additional CVE fields
- Update the table headers and data mapping as needed

## Troubleshooting

### Common Issues

1. **"Module not found" errors**: Run `npm install` to install dependencies
2. **API connection errors**: Ensure your backend server is running at `http://localhost:5000`
3. **Build errors**: Check that all import paths are correct and components exist

### Development Tips

- Use React Developer Tools browser extension for debugging
- Check browser console for error messages
- Verify API responses using browser Network tab

## Future Enhancements

- [ ] Implement actual report download functionality
- [ ] Add filtering and sorting options
- [ ] Include vulnerability scoring (CVSS)
- [ ] Add user authentication and saved searches
- [ ] Implement real-time vulnerability monitoring
- [ ] Add export options (CSV, PDF, JSON)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is open source and available under the MIT License.

## Support

For questions or issues, please check the troubleshooting section above or create an issue in the project repository.

