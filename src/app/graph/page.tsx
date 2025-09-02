'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { RefreshCw, Network, Shield, AlertTriangle, Eye, Database, Activity } from 'lucide-react';
import dynamic from 'next/dynamic';

// Dynamically import D3 graph component to avoid SSR issues
const ForceGraph = dynamic(() => import('./components/ForceGraph'), { ssr: false });

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
}

interface IOCEdge {
  source: string;
  target: string;
  relationship: string;
  confidence: number;
  source_feed: string;
}

interface GraphData {
  nodes: IOCNode[];
  links: IOCEdge[];
}

interface GraphStats {
  totalNodes: number;
  totalEdges: number;
  criticalThreats: number;
  nodeTypes: {
    file: number;
    domain: number;
    ip: number;
    hash: number;
  };
  threatLevels: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export default function GraphVisualizationPage() {
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedNode, setSelectedNode] = useState<IOCNode | null>(null);
  const [stats, setStats] = useState<GraphStats>({
    totalNodes: 0,
    totalEdges: 0,
    criticalThreats: 0,
    nodeTypes: { file: 0, domain: 0, ip: 0, hash: 0 },
    threatLevels: { critical: 0, high: 0, medium: 0, low: 0 }
  });

  const fetchGraphData = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/graph/ioc-relationships', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
      });

      if (!response.ok) {
        throw new Error('Failed to fetch graph data');
      }

      const data = await response.json();
      setGraphData(data.graph);
      setStats(data.stats);
      setLastUpdated(new Date());
    } catch (error) {
      console.error('Error fetching graph data:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  // Auto-refresh every 5 minutes
  useEffect(() => {
    fetchGraphData();
    
    if (autoRefresh) {
      const interval = setInterval(fetchGraphData, 5 * 60 * 1000);
      return () => clearInterval(interval);
    }
  }, [fetchGraphData, autoRefresh]);

  const handleNodeClick = (node: IOCNode) => {
    setSelectedNode(node);
  };

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

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Network className="h-8 w-8 text-blue-400" />
            <div>
              <h1 className="text-3xl font-bold text-white">IOC Network Analysis</h1>
              <p className="text-slate-300">Interactive visualization of threat intelligence relationships</p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <Button
              onClick={fetchGraphData}
              disabled={loading}
              variant="outline"
              className="border-slate-600 text-white hover:bg-slate-700"
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button
              onClick={() => setAutoRefresh(!autoRefresh)}
              variant={autoRefresh ? "default" : "outline"}
              className={autoRefresh ? "bg-green-600 hover:bg-green-700" : "border-slate-600 text-white hover:bg-slate-700"}
            >
              <Activity className="h-4 w-4 mr-2" />
              Auto-Refresh
            </Button>
          </div>
        </div>

        {/* Status Bar */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardContent className="p-4">
              <div className="flex items-center space-x-3">
                <Database className="h-8 w-8 text-blue-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{stats.totalNodes}</p>
                  <p className="text-sm text-slate-300">Total Nodes</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardContent className="p-4">
              <div className="flex items-center space-x-3">
                <Network className="h-8 w-8 text-green-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{stats.totalEdges}</p>
                  <p className="text-sm text-slate-300">Total Edges</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardContent className="p-4">
              <div className="flex items-center space-x-3">
                <AlertTriangle className="h-8 w-8 text-red-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{stats.criticalThreats}</p>
                  <p className="text-sm text-slate-300">Critical Threats</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardContent className="p-4">
              <div className="flex items-center space-x-3">
                <Shield className="h-8 w-8 text-orange-400" />
                <div>
                  <p className="text-2xl font-bold text-white">
                    {lastUpdated ? lastUpdated.toLocaleTimeString() : 'Never'}
                  </p>
                  <p className="text-sm text-slate-300">Last Updated</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Graph Visualization */}
          <div className="lg:col-span-3">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <Network className="h-5 w-5 mr-2 text-blue-400" />
                  IOC Relationship Graph
                  <Badge variant="secondary" className="ml-auto bg-green-500/20 text-green-300">
                    Live Data
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-[600px] bg-slate-900/50 rounded-lg relative">
                  {loading ? (
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="flex items-center space-x-3">
                        <RefreshCw className="h-6 w-6 animate-spin text-blue-400" />
                        <span className="text-white">Loading IOC relationships...</span>
                      </div>
                    </div>
                  ) : (
                    <ForceGraph
                      data={graphData}
                      onNodeClick={handleNodeClick}
                      selectedNode={selectedNode}
                    />
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Side Panel */}
          <div className="space-y-6">
            {/* Legend */}
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white text-sm">Legend</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Node Types */}
                <div>
                  <h4 className="text-sm font-medium text-slate-300 mb-2">Node Types</h4>
                  <div className="space-y-2">
                    {Object.entries(stats.nodeTypes).map(([type, count]) => (
                      <div key={type} className="flex items-center justify-between text-xs">
                        <div className="flex items-center space-x-2">
                          <span className="text-lg">{getNodeTypeIcon(type)}</span>
                          <span className="text-slate-300 capitalize">{type}</span>
                        </div>
                        <Badge variant="outline" className="text-xs">
                          {count}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Threat Levels */}
                <div>
                  <h4 className="text-sm font-medium text-slate-300 mb-2">Threat Levels</h4>
                  <div className="space-y-2">
                    {Object.entries(stats.threatLevels).map(([level, count]) => (
                      <div key={level} className="flex items-center justify-between text-xs">
                        <div className="flex items-center space-x-2">
                          <div
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: getThreatLevelColor(level) }}
                          />
                          <span className="text-slate-300 capitalize">{level}</span>
                        </div>
                        <Badge variant="outline" className="text-xs">
                          {count}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Selected Node Details */}
            {selectedNode && (
              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white text-sm flex items-center">
                    <Eye className="h-4 w-4 mr-2" />
                    Node Details
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <p className="text-xs text-slate-400">Type</p>
                    <div className="flex items-center space-x-2">
                      <span className="text-lg">{getNodeTypeIcon(selectedNode.type)}</span>
                      <span className="text-sm text-white capitalize">{selectedNode.type}</span>
                    </div>
                  </div>

                  <div>
                    <p className="text-xs text-slate-400">Value</p>
                    <p className="text-sm text-white font-mono break-all">{selectedNode.value}</p>
                  </div>

                  <div>
                    <p className="text-xs text-slate-400">Threat Level</p>
                    <Badge
                      variant="outline"
                      className="text-xs"
                      style={{ 
                        borderColor: getThreatLevelColor(selectedNode.threatLevel),
                        color: getThreatLevelColor(selectedNode.threatLevel)
                      }}
                    >
                      {selectedNode.threatLevel.toUpperCase()}
                    </Badge>
                  </div>

                  {selectedNode.detectionRatio && (
                    <div>
                      <p className="text-xs text-slate-400">Detection Ratio</p>
                      <p className="text-sm text-white">{(selectedNode.detectionRatio * 100).toFixed(1)}%</p>
                    </div>
                  )}

                  {selectedNode.confidenceScore && (
                    <div>
                      <p className="text-xs text-slate-400">Confidence Score</p>
                      <p className="text-sm text-white">{selectedNode.confidenceScore}%</p>
                    </div>
                  )}

                  <div>
                    <p className="text-xs text-slate-400">Sources</p>
                    <div className="flex flex-wrap gap-1">
                      {selectedNode.source.map((src, idx) => (
                        <Badge key={idx} variant="secondary" className="text-xs">
                          {src}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {selectedNode.malwareFamily && (
                    <div>
                      <p className="text-xs text-slate-400">Malware Family</p>
                      <p className="text-sm text-white">{selectedNode.malwareFamily}</p>
                    </div>
                  )}

                  {selectedNode.tags && selectedNode.tags.length > 0 && (
                    <div>
                      <p className="text-xs text-slate-400">Tags</p>
                      <div className="flex flex-wrap gap-1">
                        {selectedNode.tags.slice(0, 3).map((tag, idx) => (
                          <Badge key={idx} variant="outline" className="text-xs">
                            {tag}
                          </Badge>
                        ))}
                        {selectedNode.tags.length > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{selectedNode.tags.length - 3}
                          </Badge>
                        )}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
