'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { ThreatTypePieChart } from '@/components/dashboard/ThreatTypePieChart'
import { ThreatTrendChart } from '@/components/dashboard/ThreatTrendChart'
import { AlertTriangle, Shield, TrendingUp, Activity, Globe, Database } from 'lucide-react'

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
}

interface TopThreat {
  ioc: string
  type: string
  detections: number
  riskLevel: 'High' | 'Medium' | 'Low'
}

interface DashboardData {
  stats: DashboardStats
  weeklyTrends: WeeklyTrend[]
  threatTypes: ThreatData[]
  topThreats: TopThreat[]
}

export default function Dashboard() {
  const [realtimeData, setRealtimeData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true)
        setError(null)
        
        const response = await fetch('/api/dashboard')
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`)
        }
        
        const data = await response.json()
        setRealtimeData(data)
      } catch (err) {
        console.error('Error fetching dashboard data:', err)
        setError(err instanceof Error ? err.message : 'Failed to fetch dashboard data')
        
        // Fallback to mock data in case of error
        setRealtimeData({
          stats: {
            totalIOCs: 1247,
            maliciousIOCs: 892,
            cleanIOCs: 298,
            pendingIOCs: 57,
            detectionRate: 71.5
          },
          weeklyTrends: [
            { day: 'Monday', threats: 145, clean: 67, total: 212 },
            { day: 'Tuesday', threats: 189, clean: 89, total: 278 },
            { day: 'Wednesday', threats: 167, clean: 78, total: 245 },
            { day: 'Thursday', threats: 201, clean: 64, total: 265 },
            { day: 'Friday', threats: 156, clean: 92, total: 248 },
            { day: 'Saturday', threats: 134, clean: 56, total: 190 },
            { day: 'Sunday', threats: 178, clean: 71, total: 249 }
          ],
          threatTypes: [
            { type: 'Malware', count: 456, percentage: 45.6, color: '#ef4444' },
            { type: 'Phishing', count: 289, percentage: 28.9, color: '#f97316' },
            { type: 'Botnet', count: 147, percentage: 14.7, color: '#eab308' },
            { type: 'Other', count: 108, percentage: 10.8, color: '#6b7280' }
          ],
          topThreats: [
            { ioc: '192.168.1.100', type: 'IP', detections: 45, riskLevel: 'High' },
            { ioc: 'malware.exe', type: 'File Hash', detections: 38, riskLevel: 'High' },
            { ioc: 'evil.com', type: 'Domain', detections: 32, riskLevel: 'Medium' },
            { ioc: 'badactor@spam.com', type: 'Email', detections: 28, riskLevel: 'Medium' },
            { ioc: '10.0.0.50', type: 'IP', detections: 23, riskLevel: 'Low' }
          ]
        })
      } finally {
        setLoading(false)
      }
    }

    fetchDashboardData()
    
    // Set up periodic refresh
    const interval = setInterval(fetchDashboardData, 30000) // Refresh every 30 seconds
    
    return () => clearInterval(interval)
  }, [])

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
    switch (risk) {
      case 'High': return 'bg-red-500/20 text-red-300 border-red-500/30'
      case 'Medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30'
      case 'Low': return 'bg-green-500/20 text-green-300 border-green-500/30'
      default: return 'bg-gray-500/20 text-gray-300 border-gray-500/30'
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
          {/* Total IOCs */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">
                Total IOCs Analyzed
              </CardTitle>
              <Database className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">
                {realtimeData.stats?.totalIOCs?.toLocaleString() || '0'}
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Cumulative analysis count
              </p>
            </CardContent>
          </Card>

          {/* Malicious IOCs */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">
                Malicious Threats
              </CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-400">
                {realtimeData.stats?.maliciousIOCs?.toLocaleString() || '0'}
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Active security risks
              </p>
            </CardContent>
          </Card>

          {/* Clean IOCs */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">
                Clean Resources
              </CardTitle>
              <Shield className="h-4 w-4 text-green-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-400">
                {realtimeData.stats?.cleanIOCs?.toLocaleString() || '0'}
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Verified safe resources
              </p>
            </CardContent>
          </Card>

          {/* Detection Rate */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">
                Detection Rate
              </CardTitle>
              <TrendingUp className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-400">
                {realtimeData.stats?.detectionRate?.toFixed(1) || '0.0'}%
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Analysis accuracy
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

        {/* Top Threats Table */}
        <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              Top Security Threats
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-600">
                    <th className="text-left text-gray-300 pb-3">IOC</th>
                    <th className="text-left text-gray-300 pb-3">Type</th>
                    <th className="text-left text-gray-300 pb-3">Detections</th>
                    <th className="text-left text-gray-300 pb-3">Risk Level</th>
                  </tr>
                </thead>
                <tbody className="space-y-2">
                  {(realtimeData.topThreats || []).map((threat, index) => (
                    <tr key={index} className="border-b border-slate-700/50">
                      <td className="py-3">
                        <code className="text-blue-300 bg-slate-700/50 px-2 py-1 rounded text-xs">
                          {threat.ioc}
                        </code>
                      </td>
                      <td className="py-3">
                        <span className="text-gray-300">{threat.type}</span>
                      </td>
                      <td className="py-3">
                        <span className="text-white font-medium">{threat.detections}</span>
                      </td>
                      <td className="py-3">
                        <Badge className={getRiskBadgeColor(threat.riskLevel)}>
                          {threat.riskLevel}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
