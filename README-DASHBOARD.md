# ThreatBoard CVE Dashboard

A comprehensive React + Tailwind + Recharts dashboard for visualizing and analyzing Common Vulnerabilities and Exposures (CVE) data.

## ✨ Features

### 🎯 **Dashboard Layout**
- **Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices
- **Sidebar Navigation**: Left sidebar with filters and quick stats
- **Main Content Area**: Charts and data table with proper spacing

### 🔍 **Search & Filtering**
- **Global Search**: Search across CVE ID, description, and technology
- **Severity Filter**: Dropdown to filter by Critical, High, Medium, Low, or Unknown
- **Year Range Filter**: Dual range sliders for selecting publication date range
- **Real-time Filtering**: Instant results as you adjust filters

### 📊 **Data Visualization**
- **Severity Distribution Pie Chart**: Shows CVE breakdown by severity level
- **Yearly CVE Count Bar Chart**: Displays vulnerability trends over time
- **Interactive Charts**: Hover tooltips with detailed information
- **Responsive Charts**: Automatically adjust to container size

### 📋 **Data Table**
- **Paginated Results**: 10 items per page with navigation
- **Sortable Columns**: CVE ID, Description, Severity, Published Date, Technology
- **Clickable CVE IDs**: Direct links to NVD database
- **Expandable Descriptions**: "Read more" functionality for long descriptions
- **Color-coded Severity**: Visual severity indicators

### 🎨 **UI/UX Features**
- **Tailwind CSS**: Modern, responsive styling with soft shadows and rounded corners
- **Hover Effects**: Interactive elements with smooth transitions
- **Color-coded Severity**: Red (Critical), Orange (High), Yellow (Medium), Green (Low), Gray (Unknown)
- **Mobile-First Design**: Responsive layout that works on all screen sizes

## 🚀 **Quick Start**

### 1. Install Dependencies
```bash
npm install
```

### 2. Start Development Server
```bash
npm start
```

### 3. Open Browser
Navigate to `http://localhost:3000`

## 🏗️ **Project Structure**

```
src/
├── components/
│   ├── Dashboard.js           # Main dashboard component
│   ├── Sidebar.js            # Left sidebar with filters
│   ├── SearchBar.js          # Global search component
│   ├── CVETable.js           # Data table with pagination
│   ├── SeverityPieChart.js   # Pie chart for severity distribution
│   └── YearlyBarChart.js     # Bar chart for yearly CVE counts
├── App.js                    # Main app component
├── index.js                  # Application entry point
└── index.css                 # Global styles and Tailwind imports
```

## 📱 **Responsive Design**

### Desktop (1024px+)
- Full sidebar with all filters
- Two-column chart layout
- Full-width data table

### Tablet (768px - 1023px)
- Collapsible sidebar
- Single-column chart layout
- Responsive table with horizontal scroll

### Mobile (< 768px)
- Stacked layout for all components
- Touch-friendly controls
- Optimized for small screens

## 🔧 **Configuration**

### Data Source
Currently uses mock data for demonstration. To connect to your backend:

1. **Update API Endpoint**: Modify `fetchCVEData()` in `Dashboard.js`
2. **Data Format**: Ensure your API returns data in the expected format
3. **Real-time Updates**: Implement WebSocket or polling for live data

### Chart Customization
- **Colors**: Modify color schemes in chart components
- **Chart Types**: Easily swap between different Recharts components
- **Tooltips**: Customize tooltip content and styling

### Filter Options
- **Severity Levels**: Add/remove severity categories in `Sidebar.js`
- **Year Range**: Adjust min/max years in the year range filter
- **Search Fields**: Modify searchable fields in the search functionality

## 📊 **Data Format**

The dashboard expects CVE data in this format:

```json
{
  "id": "CVE-2023-1234",
  "description": "Vulnerability description...",
  "severity": "High",
  "publishedDate": "2023-01-15T00:00:00Z",
  "technology": "React",
  "cvssScore": 7.5
}
```

## 🎨 **Customization**

### Styling
- **Tailwind Classes**: Modify component classes for different looks
- **Color Scheme**: Update primary colors in `tailwind.config.js`
- **Custom CSS**: Add custom styles in `index.css`

### Components
- **Add New Charts**: Create new chart components using Recharts
- **Modify Filters**: Add new filter types in the sidebar
- **Table Columns**: Add/remove columns in the CVE table

## 🔌 **API Integration**

### Backend Requirements
- **Endpoint**: `/api/cves` (GET)
- **Response**: JSON array of CVE objects
- **CORS**: Enable cross-origin requests
- **Error Handling**: Proper HTTP status codes and error messages

### Example API Call
```javascript
const fetchCVEData = async () => {
  try {
    const response = await fetch('/api/cves');
    const data = await response.json();
    setCveData(data);
  } catch (error) {
    setError('Failed to fetch CVE data');
  }
};
```

## 📈 **Performance Features**

- **Lazy Loading**: Components load only when needed
- **Efficient Filtering**: Real-time filtering without API calls
- **Pagination**: Load only visible data
- **Memoization**: Optimized re-renders for charts

## 🧪 **Testing**

### Manual Testing
1. **Filters**: Test all filter combinations
2. **Search**: Verify search functionality across all fields
3. **Pagination**: Test table navigation
4. **Responsiveness**: Test on different screen sizes
5. **Charts**: Verify chart interactions and tooltips

### Browser Compatibility
- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## 🚀 **Deployment**

### Build for Production
```bash
npm run build
```

### Environment Variables
- `REACT_APP_API_URL`: Backend API endpoint
- `REACT_APP_CHART_COLORS`: Custom chart color scheme

### Hosting
- **Netlify**: Drag and drop `build` folder
- **Vercel**: Connect GitHub repository
- **AWS S3**: Upload static files
- **GitHub Pages**: Deploy from repository

## 🔮 **Future Enhancements**

- [ ] **Real-time Updates**: WebSocket integration for live data
- [ ] **Advanced Filtering**: Date picker, technology dropdown
- [ ] **Export Functionality**: CSV, PDF, JSON export
- [ ] **User Authentication**: Login and user preferences
- [ ] **Saved Searches**: Save and share filter combinations
- [ ] **Dark Mode**: Toggle between light and dark themes
- [ ] **More Chart Types**: Line charts, heatmaps, etc.
- [ ] **Data Comparison**: Compare CVE data across time periods

## 🐛 **Troubleshooting**

### Common Issues

1. **Charts Not Rendering**
   - Check if Recharts is properly installed
   - Verify data format matches expected structure
   - Check browser console for errors

2. **Filters Not Working**
   - Ensure filter state is properly managed
   - Check filter logic in useEffect hooks
   - Verify data filtering functions

3. **Mobile Responsiveness**
   - Test on actual mobile devices
   - Check Tailwind responsive classes
   - Verify CSS media queries

### Performance Issues
- **Large Datasets**: Implement virtual scrolling for tables
- **Slow Filtering**: Add debouncing to search inputs
- **Chart Rendering**: Use React.memo for chart components

## 📚 **Resources**

- **Recharts Documentation**: https://recharts.org/
- **Tailwind CSS**: https://tailwindcss.com/
- **React Hooks**: https://reactjs.org/docs/hooks-intro.html
- **NVD API**: https://nvd.nist.gov/developers/vulnerabilities

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 **License**

MIT License - see package.json for details.

---

**Built with ❤️ using React, Tailwind CSS, and Recharts**
