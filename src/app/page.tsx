'use client'

import React, { useState, useEffect, useRef, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { ThreatTypePieChart } from '@/components/dashboard/ThreatTypePieChart'
import { ThreatTrendChart } from '@/components/dashboard/ThreatTrendChart'
import { AlertTriangle, Shield, TrendingUp, Activity, Globe, Database, Users, ArrowUpRight, ArrowDownRight } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'

// Trend indicator component
const TrendIndicator: React.FC<{ trend: number }> = ({ trend }) => {
  const isPositive = trend > 0;
  const isNegative = trend < 0;
  
  if (Math.abs(trend) < 0.1) return null; // Don't show indicator for minimal changes
  
  return (
    <div className={`flex items-center space-x-1 text-xs ${
      isPositive ? 'text-green-400' : isNegative ? 'text-red-400' : 'text-gray-400'
    }`}>
      {isPositive ? (
        <ArrowUpRight className="h-3 w-3" />
      ) : (
        <ArrowDownRight className="h-3 w-3" />
      )}
      <span>{Math.abs(trend).toFixed(1)}%</span>
    </div>
  );
};

interface ThreatData {
  type: string
  count: number
  percentage: number
  color: string
}

interface WeeklyTrend {
  day: string
  threats: number
  clean: number
  total: number
}

interface DashboardStats {
  totalIOCs: number
  maliciousIOCs: number
  cleanIOCs: number
  pendingIOCs: number
  detectionRate: number
  activeAnalysts: number
  trends: {
    totalIOCs: number
    threatsDetected: number
    activeAnalysts: number
  }
}

interface ThreatVector {
  name: string
  count: number
  severity: string
  detectionRate: number
  riskLevel: string
  color: string
  description: string
}

interface DashboardData {
  stats: DashboardStats
  weeklyTrends: WeeklyTrend[]
  threatTypes: ThreatData[]
  threatVectors: ThreatVector[]
}

export default function Dashboard() {
  const [realtimeData, setRealtimeData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { token, isAuthenticated, loading: authLoading } = useAuth()
  const intervalRef = useRef<NodeJS.Timeout | null>(null)

  useEffect(() => {
    let isMounted = true

    const fetchData = async (authToken: string) => {
      if (!isMounted) return

      try {
        const response = await fetch('/api/dashboard', {
          headers: {
            'Authorization': `Bearer ${authToken}`,
            'Content-Type': 'application/json',
          },
        })
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`)
        }
        
        const data = await response.json()
        
        if (isMounted) {
          setRealtimeData(data)
          setError(null)
        }
      } catch (err) {
        console.error('Error fetching dashboard data:', err)
        if (isMounted) {
          setError(err instanceof Error ? err.message : 'Failed to fetch dashboard data')
        }
      }
    }

    const setupDashboard = async () => {
      if (!isMounted) return

      setLoading(true)
      setError(null)

      if (!authLoading && isAuthenticated && token) {
        try {
          // Initial fetch
          await fetchData(token)

          // Setup interval - clear any existing one first
          if (intervalRef.current) {
            clearInterval(intervalRef.current)
          }

          intervalRef.current = setInterval(() => {
            if (isMounted && token) {
              fetchData(token)
            }
          }, 30000) // 30 seconds
        } catch (err) {
          console.error('Failed to setup dashboard:', err)
        }
      }

      if (isMounted) {
        setLoading(false)
      }
    }

    // Only setup if authentication has loaded
    if (!authLoading) {
      setupDashboard()
    }

    // Cleanup function
    return () => {
      isMounted = false
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }
  }, [authLoading, isAuthenticated, token])

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-800">
        <div className="container mx-auto px-6 py-8">
          <div className="flex items-center justify-center h-96">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400 mx-auto mb-4"></div>
              <p className="text-gray-300">Loading real-time threat intelligence...</p>
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (!realtimeData || !realtimeData.stats) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-800">
        <div className="container mx-auto px-6 py-8">
          <div className="flex items-center justify-center h-96">
            <div className="text-center text-red-400">
              <AlertTriangle className="h-12 w-12 mx-auto mb-4" />
              <p>Error loading dashboard data</p>
              {error && <p className="text-sm mt-2 text-gray-400">{error}</p>}
            </div>
          </div>
        </div>
      </div>
    )
  }

  const getRiskBadgeColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'extreme': 
      case 'critical': 
        return 'bg-red-600/90 text-red-100 border-red-500/50 shadow-lg shadow-red-500/25'
      case 'high': 
        return 'bg-orange-500/90 text-orange-100 border-orange-400/50 shadow-lg shadow-orange-500/25'
      case 'medium': 
        return 'bg-yellow-500/90 text-yellow-100 border-yellow-400/50 shadow-lg shadow-yellow-500/25'
      case 'low': 
        return 'bg-green-500/90 text-green-100 border-green-400/50 shadow-lg shadow-green-500/25'
      default: 
        return 'bg-gray-500/90 text-gray-100 border-gray-400/50 shadow-lg shadow-gray-500/25'
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-800">
      <div className="container mx-auto px-6 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-blue-500/20">
              <Shield className="h-8 w-8 text-blue-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">
                IOC Analyzer Pro Dashboard
              </h1>
              <p className="text-gray-300 mt-1">
                Real-time threat intelligence and security monitoring
                {error && (
                  <span className="ml-2 text-yellow-400 text-sm">
                    (Fallback data - API connection issue)
                  </span>
                )}
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-2 text-sm text-gray-400">
            <Activity className="h-4 w-4" />
            <span>Live monitoring active</span>
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Total IOCs Analyzed */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">
                Total IOCs Analyzed
              </CardTitle>
              <Database className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="text-2xl font-bold text-white">
                  {realtimeData.stats?.totalIOCs?.toLocaleString() || '0'}
                </div>
                <TrendIndicator trend={realtimeData.stats?.trends?.totalIOCs || 0} />
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Cumulative analysis count
              </p>
            </CardContent>
          </Card>

          {/* Threats Detected */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">
                Threats Detected
              </CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="text-2xl font-bold text-red-400">
                  {realtimeData.stats?.maliciousIOCs?.toLocaleString() || '0'}
                </div>
                <TrendIndicator trend={realtimeData.stats?.trends?.threatsDetected || 0} />
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Active security risks
              </p>
            </CardContent>
          </Card>

          {/* Active Analysts */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">
                Active Analysts
              </CardTitle>
              <Users className="h-4 w-4 text-purple-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="text-2xl font-bold text-purple-400">
                  {realtimeData.stats?.activeAnalysts?.toLocaleString() || '0'}
                </div>
                <TrendIndicator trend={realtimeData.stats?.trends?.activeAnalysts || 0} />
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Currently online
              </p>
            </CardContent>
          </Card>

          {/* Clean Resources */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">
                Clean Resources
              </CardTitle>
              <Shield className="h-4 w-4 text-green-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="text-2xl font-bold text-green-400">
                  {realtimeData.stats?.cleanIOCs?.toLocaleString() || '0'}
                </div>
                {/* No trend for clean resources as it's less critical */}
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Verified safe resources
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Charts and Analysis */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* Threat Types Distribution */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Globe className="h-5 w-5 text-blue-400" />
                Threat Distribution Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ThreatTypePieChart data={(realtimeData.threatTypes || []).map(threat => ({
                name: threat.type,
                value: threat.percentage,
                color: threat.color,
                count: threat.count,
                description: `${threat.type} threats detected in the system`
              }))} />
            </CardContent>
          </Card>

          {/* Weekly Trends */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <TrendingUp className="h-5 w-5 text-green-400" />
                Weekly Detection Trends
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ThreatTrendChart data={realtimeData.weeklyTrends} />
            </CardContent>
          </Card>
        </div>

        {/* Top Threats Cards */}
        <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              Top Threats (Last 24h)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="max-h-96 overflow-y-auto space-y-3" style={{ scrollbarWidth: 'thin', scrollbarColor: '#8b5cf6 #374151' }}>
              {(realtimeData.threatVectors && realtimeData.threatVectors.length > 0) ? (
                <>
                  {realtimeData.threatVectors.slice(0, 10).map((threat, index) => (
                    <div key={index} className="bg-slate-700/30 rounded-lg p-4 border border-slate-600/50 hover:bg-slate-600/30 transition-all duration-200">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3 flex-1">
                          <div className="flex-shrink-0">
                            <AlertTriangle className={`h-5 w-5 ${threat.count > 0 ? 'text-red-400' : 'text-gray-500'}`} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="text-white font-medium text-base mb-1">
                              {threat.name}.Generic.{threat.severity?.charAt(0).toUpperCase() + threat.severity?.slice(1) || 'Unknown'}
                            </div>
                            <div className="text-gray-400 text-sm">
                              {threat.count > 0 ? `${threat.count} detections` : 'No samples analyzed yet'}
                            </div>
                            <div className="text-xs text-gray-500 mt-1">
                              {threat.description}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3 flex-shrink-0 ml-4">
                          <div className="w-24 bg-slate-600 rounded-full h-1.5">
                            <div 
                              className={`${threat.count > 0 ? 'bg-gradient-to-r from-red-500 to-orange-500' : 'bg-gray-600'} h-1.5 rounded-full transition-all duration-300`}
                              style={{ width: `${threat.count > 0 ? Math.min(100, threat.detectionRate) : 0}%` }}
                            ></div>
                          </div>
                          <Badge 
                            className={`${threat.count > 0 ? getRiskBadgeColor(threat.riskLevel) : 'bg-gray-600/90 text-gray-300 border-gray-500/50'} px-3 py-1 text-sm font-medium`}
                          >
                            {threat.count > 0 ? threat.riskLevel : 'N/A'}
                          </Badge>
                        </div>
                      </div>
                    </div>
                  ))}
                  {realtimeData.threatVectors.every(threat => threat.count === 0) && (
                    <div className="text-center py-8 bg-slate-700/20 rounded-lg border border-slate-600/30">
                      <div className="text-gray-400">
                        <AlertTriangle className="h-8 w-8 mx-auto mb-3 opacity-50" />
                        <p className="text-base font-medium mb-2">Ready for Threat Analysis</p>
                        <p className="text-sm">Visit the <a href="/analyze" className="text-blue-400 hover:text-blue-300 underline">Analysis Page</a> to submit IOCs and see threat categorization here.</p>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="text-center py-12">
                  <div className="text-gray-400">
                    <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p className="text-lg">No threats detected in the last 24 hours</p>
                    <p className="text-sm mt-2">Your system appears secure</p>
                  </div>
                </div>
              )}
            </div>
            {realtimeData.threatVectors && realtimeData.threatVectors.length > 5 && (
              <div className="mt-4 text-center text-xs text-gray-400 border-t border-slate-600/30 pt-3">
                Showing {realtimeData.threatVectors.length} threat categories • Scroll to see all
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
