'use client';

import React, { useState, useMemo, useCallback } from 'react';
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
  themeMode?: 'dark' | 'light';
}

export function ThreatTypePieChart({ data, themeMode = 'dark' }: ThreatTypePieChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  // Static default data - prevent unnecessary re-renders
  const defaultData: ThreatTypeData[] = useMemo(() => [
    { name: 'Trojans', value: 35, color: 'rgb(239,68,68)', count: 432, description: 'Malicious programs that disguise themselves' },
    { name: 'Malware', value: 28, color: 'rgb(249,115,22)', count: 346, description: 'Generic malicious software' },
    { name: 'Ransomware', value: 18, color: 'rgb(234,179,8)', count: 222, description: 'Encrypts files for ransom' },
    { name: 'Adware', value: 12, color: 'rgb(34,197,94)', count: 148, description: 'Displays unwanted advertisements' },
    { name: 'Other', value: 7, color: 'rgb(147,51,234)', count: 86, description: 'Other threat types' }
  ], []);

  // Always create fresh data reference - never mutate
  const threatTypeData = useMemo(() => {
    if (!data) return defaultData;
    // Create completely new array with new objects to ensure reactivity
    return data.map(item => ({ ...item }));
  }, [data, defaultData]);

  // Extract colors for version key
  const colors = useMemo(() => threatTypeData.map(d => d.color), [threatTypeData]);
  
  // Comprehensive version key to force re-render on any change
  const chartVersion = useMemo(() => {
    return JSON.stringify({
      data: threatTypeData.map(d => ({ name: d.name, value: d.value, count: d.count })),
      colors,
      themeMode,
      timestamp: Date.now() // Force update on every render cycle
    });
  }, [threatTypeData, colors, themeMode]);

  // Custom tooltip component defined INSIDE to pick up prop/state changes immediately
  const CustomTooltip = useCallback(({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const tooltipData = payload[0].payload;
      return (
        <div className="bg-slate-900 border-2 border-slate-600 rounded-md p-3 shadow-2xl backdrop-blur-sm">
          <div className="flex items-center gap-3 mb-3">
            <div 
              className="w-4 h-4 rounded-full border border-slate-400 shadow-sm" 
              style={{ backgroundColor: tooltipData.color }}
            />
            <span className="text-white font-semibold text-base tracking-wide">{tooltipData.name}</span>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-6">
              <span className="text-gray-200 text-sm font-medium">Count:</span>
              <span className="text-white font-bold text-sm">{tooltipData.count?.toLocaleString()}</span>
            </div>
            <div className="flex items-center justify-between gap-6">
              <span className="text-gray-200 text-sm font-medium">Percentage:</span>
              <span className="text-white font-bold text-sm">{tooltipData.value}%</span>
            </div>
            <div className="border-t border-slate-600 mt-3 pt-3">
              <p className="text-gray-200 text-sm leading-relaxed font-medium">{tooltipData.description}</p>
            </div>
          </div>
        </div>
      );
    }
    return null;
  }, []);

  // Memoized event handlers to prevent unnecessary re-renders
  const handleMouseEnter = useCallback((_: any, index: number) => {
    setHoveredIndex(index);
  }, []);

  const handleMouseLeave = useCallback(() => {
    setHoveredIndex(null);
  }, []);

  const handleLegendMouseEnter = useCallback((index: number) => {
    setHoveredIndex(index);
  }, []);

  const handleLegendMouseLeave = useCallback(() => {
    setHoveredIndex(null);
  }, []);

  return (
    <div className="w-full">
      <div className="mb-4">
        <h3 className="text-xl font-semibold text-white mb-2">Threat Types</h3>
        <p className="text-gray-400 text-sm">Distribution by category</p>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart key={chartVersion}>
              <Pie
                data={threatTypeData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                paddingAngle={2}
                dataKey="value"
                onMouseEnter={handleMouseEnter}
                onMouseLeave={handleMouseLeave}
                isAnimationActive={true}
                animationBegin={0}
                animationDuration={300}
              >
                {threatTypeData.map((entry, index) => (
                  <Cell 
                    key={`cell-${entry.name}-${index}-${chartVersion.slice(-8)}`}
                    fill={entry.color}
                    style={{
                      filter: hoveredIndex === index ? 'brightness(1.1)' : 'brightness(1)',
                      transition: 'all 0.2s ease-in-out',
                      cursor: 'pointer'
                    }}
                  />
                ))}
              </Pie>
              <Tooltip 
                content={<CustomTooltip />}
                cursor={false}
                wrapperStyle={{ outline: 'none', zIndex: 1000 }}
                allowEscapeViewBox={{ x: false, y: false }}
                offset={10}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="flex flex-col justify-center space-y-1.5">
          {threatTypeData.map((item, index) => (
            <div 
              key={`legend-${item.name}-${index}-${chartVersion.slice(-8)}`}
              className={`flex items-center justify-between p-3 rounded-lg transition-all duration-300 cursor-pointer ${
                hoveredIndex === index 
                  ? 'bg-slate-600/60 border border-slate-500/50 shadow-sm' 
                  : 'hover:bg-slate-700/40 hover:border hover:border-slate-600/30'
              }`}
              onMouseEnter={() => handleLegendMouseEnter(index)}
              onMouseLeave={handleLegendMouseLeave}
            >
              <div className="flex items-center gap-3">
                <div 
                  className="w-3 h-3 rounded-full border border-slate-400/50"
                  style={{ backgroundColor: item.color }}
                />
                <div>
                  <div className={`text-sm font-medium transition-colors duration-300 ${
                    hoveredIndex === index ? 'text-white' : 'text-gray-200'
                  }`}>
                    {item.name}
                  </div>
                  <div className={`text-xs transition-colors duration-300 ${
                    hoveredIndex === index ? 'text-gray-300' : 'text-gray-400'
                  }`}>
                    {item.count.toLocaleString()} detections
                  </div>
                </div>
              </div>
              <div className={`text-sm font-bold transition-colors duration-300 ${
                hoveredIndex === index ? 'text-white' : 'text-gray-200'
              }`}>
                {item.value}%
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
