'use client';

import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { 
  Search, Hash, Globe, Network, BarChart3, TrendingUp, AlertTriangle
} from 'lucide-react';
import { toast } from 'sonner';
import { PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts';

const formSchema = z.object({
  iocs: z.string().min(1, 'At least one IOC is required'),
});

type FormData = z.infer<typeof formSchema>;

interface DashboardData {
  stats: {
    totalIOCs: number;
    maliciousIOCs: number;
    cleanIOCs: number;
    pendingIOCs: number;
    detectionRate: number;
  };
  weeklyTrends: Array<{
    day: string;
    threats: number;
    clean: number;
    total: number;
  }>;
  threatTypes: Array<{
    type: string;
    count: number;
    percentage: number;
    color: string;
  }>;
}

export default function AnalyzePage() {
  const [activeSearchType, setActiveSearchType] = useState<'auto' | 'hash' | 'domain' | 'ip'>('auto');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);

  const form = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      iocs: '',
    },
  });

  // Fetch real-time dashboard data
  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const response = await fetch('/api/dashboard');
        if (response.ok) {
          const data = await response.json();
          setDashboardData(data);
        }
      } catch (error) {
        console.error('Failed to fetch dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
    // Refresh data every 30 seconds
    const interval = setInterval(fetchDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  const onSubmit = async (data: FormData) => {
    setIsSubmitting(true);
    try {
      const iocList = data.iocs
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);

      const response = await fetch('/api/ioc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          iocs: iocList,
          label: 'Threat Hunt Analysis'
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      toast.success(`Analysis completed! ${result.created} new IOCs analyzed.`);
    } catch (error) {
      console.error('Analysis failed:', error);
      toast.error('Analysis failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const searchTypes = [
    { id: 'auto', label: 'Auto', icon: Search },
    { id: 'hash', label: 'Hash', icon: Hash },
    { id: 'domain', label: 'Domain', icon: Globe },
    { id: 'ip', label: 'IP', icon: Network },
  ];

  // Prepare pie chart data from real data
  const pieChartData = dashboardData?.threatTypes?.map(threat => ({
    name: threat.type,
    value: threat.count,
    color: threat.color
  })) || [];

  // Prepare line chart data from real data
  const lineChartData = dashboardData?.weeklyTrends?.map(day => ({
    name: day.day.slice(0, 3), // Mon, Tue, etc.
    threats: day.threats,
    clean: day.clean
  })) || [];

  // Get real threat vector data
  const threatVectorData = [
    { 
      name: 'Malicious', 
      count: dashboardData?.stats?.maliciousIOCs || 0, 
      severity: 'critical',
      percentage: dashboardData?.stats?.totalIOCs ? Math.round((dashboardData.stats.maliciousIOCs / dashboardData.stats.totalIOCs) * 100) : 0
    },
    { 
      name: 'Clean', 
      count: dashboardData?.stats?.cleanIOCs || 0, 
      severity: 'low',
      percentage: dashboardData?.stats?.totalIOCs ? Math.round((dashboardData.stats.cleanIOCs / dashboardData.stats.totalIOCs) * 100) : 0
    },
    { 
      name: 'Pending', 
      count: dashboardData?.stats?.pendingIOCs || 0, 
      severity: 'medium',
      percentage: dashboardData?.stats?.totalIOCs ? Math.round((dashboardData.stats.pendingIOCs / dashboardData.stats.totalIOCs) * 100) : 0
    },
    { 
      name: 'Total IOCs', 
      count: dashboardData?.stats?.totalIOCs || 0, 
      severity: 'high',
      percentage: 100
    },
    { 
      name: 'Detection Rate', 
      count: dashboardData?.stats?.detectionRate ? Math.round(dashboardData.stats.detectionRate) : 0, 
      severity: dashboardData?.stats?.detectionRate && dashboardData.stats.detectionRate > 90 ? 'low' : 'medium',
      percentage: dashboardData?.stats?.detectionRate || 0,
      isPercentage: true
    },
  ];

  if (loading) {
    return (
      <div className="space-y-6 p-6">
        <div className="flex items-center justify-center min-h-[400px]">
          <div className="text-white">Loading real-time data...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Threat Hunting</h1>
          <p className="text-slate-400">Advanced threat intelligence with real-time analysis</p>
        </div>
        <div className="flex items-center space-x-6">
          <div className="text-right">
            <div className="text-2xl font-bold text-red-400">
              {dashboardData?.stats?.maliciousIOCs || 0}
            </div>
            <div className="text-sm text-slate-400">Active Threats</div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-green-400">
              {dashboardData?.stats?.detectionRate ? `${dashboardData.stats.detectionRate.toFixed(1)}%` : '0%'}
            </div>
            <div className="text-sm text-slate-400">Detection Rate</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6">
        {/* IOC Intelligence Search - Full Width */}
        <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm hover:bg-slate-800/70 hover:border-slate-600 transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/10">
          <CardHeader>
            <CardTitle className="text-white flex items-center space-x-2">
              <Search className="h-5 w-5 text-blue-400" />
              <span>IOC Intelligence Search</span>
              <Badge variant="secondary" className="ml-auto bg-blue-500/20 text-blue-300">Live</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Search Type Selector */}
            <div className="grid grid-cols-4 gap-2">
              {searchTypes.map((type) => (
                <Button
                  key={type.id}
                  variant={activeSearchType === type.id ? "default" : "outline"}
                  className={`flex flex-col items-center p-3 h-auto space-y-1 text-xs transition-all duration-200 hover:scale-105 ${
                    activeSearchType === type.id 
                      ? 'bg-blue-500 text-white border-none shadow-lg shadow-blue-500/25' 
                      : 'bg-slate-700/50 border-slate-600 text-slate-300 hover:bg-slate-600/50 hover:border-slate-500'
                  }`}
                  onClick={() => setActiveSearchType(type.id as any)}
                >
                  <type.icon className="h-4 w-4" />
                  <span>{type.label}</span>
                </Button>
              ))}
            </div>

            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="iocs"
                  render={({ field }) => (
                    <FormItem>
                      <FormControl>
                        <Textarea
                          {...field}
                          placeholder="Enter IOC (hash, domain, IP, URL)...&#10;&#10;Try searching:&#10;test&#10;bd9948b278b2a31725e6eb9a37b9fe8f7e654c74"
                          className="min-h-[100px] bg-slate-900/50 border-slate-600 text-white placeholder:text-slate-500 resize-none hover:border-slate-500 focus:border-blue-500 transition-all duration-200"
                          disabled={isSubmitting}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <Button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white border-none transition-all duration-200 hover:scale-105 hover:shadow-lg hover:shadow-blue-500/25"
                >
                  {isSubmitting ? 'Analyzing...' : 'Hunt'}
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Detection Overview */}
        <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm hover:bg-slate-800/70 hover:border-slate-600 transition-all duration-300 hover:shadow-lg hover:shadow-green-500/10">
          <CardHeader>
            <CardTitle className="text-white flex items-center space-x-2">
              <BarChart3 className="h-5 w-5 text-green-400" />
              <span>Threat Detection Overview</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {pieChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'rgba(0, 0, 0, 0.9)',
                      border: '1px solid rgb(99, 102, 241)',
                      borderRadius: '8px',
                      color: 'white',
                      fontWeight: '500',
                      boxShadow: '0 10px 25px rgba(0, 0, 0, 0.5)'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* 24H Threat Trends */}
        <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm hover:bg-slate-800/70 hover:border-slate-600 transition-all duration-300 hover:shadow-lg hover:shadow-red-500/10">
          <CardHeader>
            <CardTitle className="text-white flex items-center space-x-2">
              <TrendingUp className="h-5 w-5 text-red-400" />
              <span>24H Threat Trends</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={lineChartData}>
                  <XAxis 
                    dataKey="name" 
                    axisLine={false}
                    tickLine={false}
                    tick={{ fill: 'rgb(156, 163, 175)', fontSize: 12 }}
                  />
                  <YAxis 
                    axisLine={false}
                    tickLine={false}
                    tick={{ fill: 'rgb(156, 163, 175)', fontSize: 12 }}
                  />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'rgb(30, 41, 59)',
                      border: '1px solid rgb(71, 85, 105)',
                      borderRadius: '8px',
                      color: 'white'
                    }}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="threats" 
                    stroke="rgb(239, 68, 68)" 
                    strokeWidth={3}
                    dot={{ fill: 'rgb(239, 68, 68)', strokeWidth: 2, r: 4 }}
                    activeDot={{ r: 6, fill: 'rgb(239, 68, 68)' }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6">
        {/* Threat Vector Analysis - Full Width */}
        <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm hover:bg-slate-800/70 hover:border-slate-600 transition-all duration-300 hover:shadow-lg hover:shadow-orange-500/10">
          <CardHeader>
            <CardTitle className="text-white flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-orange-400" />
              <span>Threat Vector Analysis</span>
              <Badge variant="secondary" className="ml-auto bg-red-500/20 text-red-300">Live Data</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
              {threatVectorData.map((threat) => (
                <div key={threat.name} className="bg-slate-900/50 rounded-lg p-4 hover:bg-slate-900/70 transition-all duration-200 hover:scale-105 hover:shadow-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-white font-medium">{threat.name}</span>
                    <Badge className={`transition-all duration-200 hover:scale-110 ${
                      threat.severity === 'critical' ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30' :
                      threat.severity === 'high' ? 'bg-orange-500/20 text-orange-400 hover:bg-orange-500/30' :
                      threat.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30' :
                      'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                    }`}>
                      {threat.severity}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="text-2xl font-bold text-white">
                      {threat.isPercentage ? `${threat.count}%` : threat.count}
                    </div>
                    <div className="text-xs text-slate-400">
                      {threat.isPercentage ? 'Rate' : 'Count'}
                    </div>
                  </div>
                  <div className="mt-2 w-full bg-slate-700 rounded-full h-1">
                    <div 
                      className={`h-1 rounded-full transition-all duration-1000 ${
                        threat.severity === 'critical' ? 'bg-red-400' :
                        threat.severity === 'high' ? 'bg-orange-400' :
                        threat.severity === 'medium' ? 'bg-yellow-400' :
                        'bg-green-400'
                      }`}
                      style={{ width: `${threat.percentage}%` }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
