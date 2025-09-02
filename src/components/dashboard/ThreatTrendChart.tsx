'use client';

import React from 'react';
import { LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip, Legend } from 'recharts';

interface WeeklyData {
  day: string;
  threats: number;
  clean: number;
  total: number;
}

interface ThreatTrendChartProps {
  data?: WeeklyData[];
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[rgb(28,30,48)] border border-[rgb(55,65,81)] rounded-lg p-4 shadow-lg">
        <p className="text-white font-medium mb-2">{label}</p>
        <div className="space-y-1">
          {payload.map((entry: any, index: number) => (
            <div key={index} className="flex items-center gap-2">
              <div 
                className="w-3 h-3 rounded-full" 
                style={{ backgroundColor: entry.color }}
              ></div>
              <span className="text-[rgb(156,163,175)] text-sm">
                {entry.name === 'clean' ? 'Clean Files' : 'Threats'}: 
              </span>
              <span className="text-white font-medium">{entry.value.toLocaleString()}</span>
            </div>
          ))}
          <div className="border-t border-[rgb(55,65,81)] mt-2 pt-2">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-[rgb(147,51,234)]"></div>
              <span className="text-[rgb(156,163,175)] text-sm">Total:</span>
              <span className="text-white font-medium">
                {payload[0]?.payload?.total?.toLocaleString()}
              </span>
            </div>
          </div>
        </div>
      </div>
    );
  }
  return null;
};

export function ThreatTrendChart({ data }: ThreatTrendChartProps) {
  // Default data if no data is provided (fallback)
  const defaultData: WeeklyData[] = [
    { day: 'Monday', threats: 18, clean: 165, total: 183 },
    { day: 'Tuesday', threats: 22, clean: 190, total: 212 },
    { day: 'Wednesday', threats: 15, clean: 145, total: 160 },
    { day: 'Thursday', threats: 35, clean: 210, total: 245 },
    { day: 'Friday', threats: 28, clean: 175, total: 203 },
    { day: 'Saturday', threats: 19, clean: 125, total: 144 },
    { day: 'Sunday', threats: 25, clean: 160, total: 185 }
  ];

  const weeklyData = data || defaultData;

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={weeklyData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <XAxis 
            dataKey="day" 
            axisLine={false}
            tickLine={false}
            tick={{ fill: 'rgb(156,163,175)', fontSize: 12 }}
            tickFormatter={(value) => value.slice(0, 3)} // Show first 3 letters
          />
          <YAxis 
            axisLine={false}
            tickLine={false}
            tick={{ fill: 'rgb(156,163,175)', fontSize: 12 }}
            domain={[0, 'dataMax + 50']}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend 
            verticalAlign="top" 
            height={36}
            iconType="circle"
            formatter={(value) => (
              <span className="text-[rgb(156,163,175)]">
                {value === 'clean' ? 'Clean Files' : 'Threat Detections'}
              </span>
            )}
          />
          <Line 
            type="monotone" 
            dataKey="clean" 
            stroke="rgb(34,197,94)" 
            strokeWidth={2}
            dot={{ fill: 'rgb(34,197,94)', strokeWidth: 0, r: 3 }}
            activeDot={{ r: 6, fill: 'rgb(34,197,94)', strokeWidth: 2, stroke: 'rgb(20,20,32)' }}
            name="clean"
          />
          <Line 
            type="monotone" 
            dataKey="threats" 
            stroke="rgb(239,68,68)" 
            strokeWidth={2}
            dot={{ fill: 'rgb(239,68,68)', strokeWidth: 0, r: 3 }}
            activeDot={{ r: 6, fill: 'rgb(239,68,68)', strokeWidth: 2, stroke: 'rgb(20,20,32)' }}
            name="threats"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
