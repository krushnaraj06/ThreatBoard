import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const YearlyBarChart = ({ data }) => {
  // Process data for bar chart
  const processData = () => {
    const yearCounts = {};
    
    data.forEach(cve => {
      if (cve.publishedDate) {
        const year = new Date(cve.publishedDate).getFullYear();
        yearCounts[year] = (yearCounts[year] || 0) + 1;
      }
    });
    
    // Sort by year and fill missing years with 0
    const years = Object.keys(yearCounts).map(Number).sort((a, b) => a - b);
    const minYear = Math.min(...years);
    const maxYear = Math.max(...years);
    
    const result = [];
    for (let year = minYear; year <= maxYear; year++) {
      result.push({
        year: year.toString(),
        count: yearCounts[year] || 0
      });
    }
    
    return result;
  };

  const chartData = processData();

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
          <p className="font-medium text-gray-900">Year: {label}</p>
          <p className="text-gray-600">
            CVEs: <span className="font-semibold text-primary-600">{payload[0].value}</span>
          </p>
        </div>
      );
    }
    return null;
  };

  if (!chartData || chartData.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500">
        No data available for chart
      </div>
    );
  }

  return (
    <div className="w-full h-80">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
          <XAxis 
            dataKey="year" 
            stroke="#6B7280"
            fontSize={12}
            tickLine={false}
            axisLine={false}
          />
          <YAxis 
            stroke="#6B7280"
            fontSize={12}
            tickLine={false}
            axisLine={false}
            tickFormatter={(value) => value}
          />
          <Tooltip content={<CustomTooltip />} />
          <Bar 
            dataKey="count" 
            fill="#3B82F6"
            radius={[4, 4, 0, 0]}
            className="hover:opacity-80 transition-opacity duration-200"
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default YearlyBarChart;
