'use client';

import React, { useEffect, useRef, useState } from 'react';

interface IOCNode {
  id: string;
  type: 'file' | 'domain' | 'ip' | 'hash';
  value: string;
  threatLevel: 'critical' | 'high' | 'medium' | 'low';
  detectionRatio?: number;
  confidenceScore?: number;
  source: string[];
  firstSeen?: string;
  lastSeen?: string;
  malwareFamily?: string;
  tags?: string[];
  x?: number;
  y?: number;
}

interface IOCEdge {
  source: string | IOCNode;
  target: string | IOCNode;
  relationship: string;
  confidence: number;
  source_feed: string;
}

interface GraphData {
  nodes: IOCNode[];
  links: IOCEdge[];
}

interface ForceGraphProps {
  data: GraphData;
  onNodeClick: (node: IOCNode) => void;
  selectedNode: IOCNode | null;
}

export default function ForceGraph({ data, onNodeClick, selectedNode }: ForceGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#d97706';
      case 'low': return '#65a30d';
      default: return '#6b7280';
    }
  };

  const getNodeTypeIcon = (type: string) => {
    switch (type) {
      case 'file': return '📄';
      case 'domain': return '🌐';
      case 'ip': return '🖥️';
      case 'hash': return '#️⃣';
      default: return '❓';
    }
  };

  // Simple physics-based layout
  useEffect(() => {
    if (!data.nodes.length) return;

    const width = 800;
    const height = 600;
    const centerX = width / 2;
    const centerY = height / 2;

    // Create a circular layout for nodes
    const nodePositions = data.nodes.map((node, index) => {
      const angle = (index / data.nodes.length) * 2 * Math.PI;
      const radius = Math.min(width, height) * 0.3;
      
      return {
        ...node,
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius
      };
    });

    // Update node positions
    data.nodes.forEach((node, index) => {
      node.x = nodePositions[index].x;
      node.y = nodePositions[index].y;
    });
  }, [data]);

  if (data.nodes.length === 0) {
    return (
      <div className="w-full h-full flex flex-col items-center justify-center">
        <div className="text-center space-y-4">
          <div className="text-6xl text-slate-500">🔍</div>
          <div>
            <h3 className="text-lg font-semibold text-white mb-2">No IOC Data Available</h3>
            <p className="text-slate-400 text-sm">
              Graph visualization will appear here when IOC relationships are detected.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <svg
      ref={svgRef}
      width="100%"
      height="100%"
      viewBox="0 0 800 600"
      className="bg-slate-900/50 rounded-lg"
    >
      {/* Render links */}
      {data.links.map((link, index) => {
        const sourceNode = typeof link.source === 'string' 
          ? data.nodes.find(n => n.id === link.source)
          : link.source;
        const targetNode = typeof link.target === 'string' 
          ? data.nodes.find(n => n.id === link.target)
          : link.target;
        
        if (!sourceNode || !targetNode) return null;
        
        const isConnectedToHovered = hoveredNode && 
          (sourceNode.id === hoveredNode || targetNode.id === hoveredNode);
        
        return (
          <g key={index}>
            <line
              x1={sourceNode.x || 0}
              y1={sourceNode.y || 0}
              x2={targetNode.x || 0}
              y2={targetNode.y || 0}
              stroke={isConnectedToHovered ? '#60a5fa' : '#64748b'}
              strokeWidth={1 + (link.confidence * 2)}
              strokeOpacity={isConnectedToHovered ? 0.8 : 0.4}
            />
            {/* Link label */}
            <text
              x={((sourceNode.x || 0) + (targetNode.x || 0)) / 2}
              y={((sourceNode.y || 0) + (targetNode.y || 0)) / 2}
              textAnchor="middle"
              fontSize="10"
              fill="#94a3b8"
              opacity={isConnectedToHovered ? 1 : 0}
              className="pointer-events-none"
            >
              {link.relationship.replace('_', ' ')}
            </text>
          </g>
        );
      })}

      {/* Render nodes */}
      {data.nodes.map((node) => {
        const isSelected = selectedNode?.id === node.id;
        const isHovered = hoveredNode === node.id;
        const radius = isHovered ? 30 : 25;
        
        return (
          <g
            key={node.id}
            transform={`translate(${node.x || 0}, ${node.y || 0})`}
            className="cursor-pointer"
            onClick={() => onNodeClick(node)}
            onMouseEnter={() => setHoveredNode(node.id)}
            onMouseLeave={() => setHoveredNode(null)}
          >
            {/* Node circle */}
            <circle
              r={radius}
              fill={getThreatLevelColor(node.threatLevel)}
              stroke={isSelected ? '#3b82f6' : '#1e293b'}
              strokeWidth={isSelected ? 4 : 2}
              className="transition-all duration-200"
            />
            
            {/* Node icon */}
            <text
              textAnchor="middle"
              dy="0.35em"
              fontSize="16"
              className="pointer-events-none select-none"
            >
              {getNodeTypeIcon(node.type)}
            </text>
            
            {/* Node label */}
            <text
              textAnchor="middle"
              dy="45"
              fontSize="10"
              fontWeight="bold"
              fill="#ffffff"
              stroke="#000000"
              strokeWidth="0.5"
              className="pointer-events-none select-none"
            >
              {node.type === 'ip' ? node.value :
               node.type === 'domain' ? (node.value.length > 12 ? node.value.substring(0, 12) + '...' : node.value) :
               node.value.substring(0, 8) + '...'}
            </text>
            
            {/* Connection count badge */}
            {data.links.filter(link => 
              (typeof link.source === 'string' ? link.source : link.source.id) === node.id ||
              (typeof link.target === 'string' ? link.target : link.target.id) === node.id
            ).length > 0 && (
              <circle
                cx="20"
                cy="-20"
                r="8"
                fill="#3b82f6"
                className="pointer-events-none"
              />
            )}
            {data.links.filter(link => 
              (typeof link.source === 'string' ? link.source : link.source.id) === node.id ||
              (typeof link.target === 'string' ? link.target : link.target.id) === node.id
            ).length > 0 && (
              <text
                x="20"
                y="-16"
                textAnchor="middle"
                fontSize="8"
                fill="white"
                className="pointer-events-none select-none"
              >
                {data.links.filter(link => 
                  (typeof link.source === 'string' ? link.source : link.source.id) === node.id ||
                  (typeof link.target === 'string' ? link.target : link.target.id) === node.id
                ).length}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}
