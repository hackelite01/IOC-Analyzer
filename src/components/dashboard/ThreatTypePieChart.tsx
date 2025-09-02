'use client';

import React, { useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

interface ThreatTypeData {
  name: string;
  value: number;
  color: string;
  count: number;
  description: string;
}

interface ThreatTypePieChartProps {
  data?: ThreatTypeData[];
}

export function ThreatTypePieChart({ data }: ThreatTypePieChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const defaultData: ThreatTypeData[] = [
    { name: 'Trojans', value: 35, color: 'rgb(239,68,68)', count: 432, description: 'Malicious programs that disguise themselves' },
    { name: 'Malware', value: 28, color: 'rgb(249,115,22)', count: 346, description: 'Generic malicious software' },
    { name: 'Ransomware', value: 18, color: 'rgb(234,179,8)', count: 222, description: 'Encrypts files for ransom' },
    { name: 'Adware', value: 12, color: 'rgb(34,197,94)', count: 148, description: 'Displays unwanted advertisements' },
    { name: 'Other', value: 7, color: 'rgb(147,51,234)', count: 86, description: 'Other threat types' }
  ];

  const threatTypeData = data || defaultData;

  return (
    <div className="w-full">
      <div className="mb-4">
        <h3 className="text-xl font-semibold text-white mb-2">Threat Types</h3>
        <p className="text-[rgb(156,163,175)] text-sm">Distribution by category</p>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={threatTypeData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                paddingAngle={2}
                dataKey="value"
                onMouseEnter={(_, index) => setHoveredIndex(index)}
                onMouseLeave={() => setHoveredIndex(null)}
              >
                {threatTypeData.map((entry, index) => (
                  <Cell 
                    key={`cell-${index}`} 
                    fill={entry.color}
                    style={{
                      filter: hoveredIndex === index ? 'brightness(1.1)' : 'brightness(1)',
                      transition: 'all 0.2s ease-in-out'
                    }}
                  />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="flex flex-col justify-center space-y-1.5">
          {threatTypeData.map((item, index) => (
            <div 
              key={index} 
              className="flex items-center justify-between p-2 rounded-md transition-all duration-300 hover:bg-[rgb(35,39,64)] cursor-pointer"
              onMouseEnter={() => setHoveredIndex(index)}
              onMouseLeave={() => setHoveredIndex(null)}
            >
              <div className="flex items-center gap-2">
                <div 
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: item.color }}
                ></div>
                <div>
                  <div className="text-white text-xs font-medium">{item.name}</div>
                  <div className="text-[rgb(156,163,175)] text-xs">{item.count.toLocaleString()}</div>
                </div>
              </div>
              <div className="text-white text-xs font-bold">{item.value}%</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
