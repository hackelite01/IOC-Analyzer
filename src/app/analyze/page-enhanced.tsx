'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Search, Upload, CheckCircle, AlertCircle, Clock, Copy, Shield, TrendingUp, FileText, Activity, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, LineChart, Line, Area, AreaChart, ResponsiveContainer } from 'recharts';
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';

const formSchema = z.object({
  iocs: z.string().min(1, 'At least one IOC is required'),
  label: z.string().optional(),
});

type FormData = z.infer<typeof formSchema>;

interface SubmissionResult {
  _id: string;
  ioc: string;
  type: string;
  verdict: string;
}

interface DetailedAnalysis {
  fileInfo?: {
    name: string;
    size: number;
    type: string;
    md5: string;
    sha1: string;
    sha256: string;
    uploadDate: string;
  };
  threatClassification?: {
    primaryType: string;
    family: string;
    severity: string;
    tags: string[];
  };
  vtResults?: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    engines: Array<{
      name: string;
      verdict: string;
      status: 'detected' | 'clean';
      lastUpdate: string;
    }>;
  };
  behaviorAnalysis?: {
    fileCreation: number;
    registryModification: number;
    networkCommunication: number;
    processInjection: number;
    serviceInstallation: number;
  };
  threatTrends?: Array<{
    time: string;
    threats: number;
  }>;
  riskScore: number;
  confidence: number;
}

export default function AnalyzePage() {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<{
    total: number;
    created: number;
    fromCache: number;
    errors: string[];
    items: SubmissionResult[];
  } | null>(null);
  const [detailedAnalysis, setDetailedAnalysis] = useState<DetailedAnalysis | null>(null);

  const form = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      iocs: '',
      label: '',
    },
  });

  const onSubmit = async (data: FormData) => {
    setIsSubmitting(true);
    setProgress(0);
    setResults(null);
    setDetailedAnalysis(null);

    try {
      // Parse IOCs from textarea
      const iocList = data.iocs
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);

      // Simulate progress
      const progressInterval = setInterval(() => {
        setProgress(prev => Math.min(prev + 10, 90));
      }, 200);

      const response = await fetch('/api/ioc', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          iocs: iocList,
          label: data.label || undefined,
        }),
      });

      clearInterval(progressInterval);
      setProgress(100);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const result = await response.json();
      setResults(result);
      
      // Generate mock detailed analysis based on IOC types
      if (result.items && result.items.length > 0) {
        const firstItem = result.items[0];
        const mockAnalysis = generateMockDetailedAnalysis(firstItem);
        setDetailedAnalysis(mockAnalysis);
      }
      
      // Defensive check for errors array
      const errors = result.errors || [];
      const total = result.total || 0;
      
      if (errors.length > 0) {
        toast.error(`Analysis completed with ${errors.length} errors`);
      } else {
        toast.success(`Successfully analyzed ${total} IOCs`);
      }

    } catch (error) {
      console.error('Analysis error:', error);
      toast.error('Failed to analyze IOCs. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const generateMockDetailedAnalysis = (item: SubmissionResult): DetailedAnalysis => {
    const isHash = item.type === 'hash';
    const isIP = item.type === 'ip';
    
    const baseAnalysis: DetailedAnalysis = {
      riskScore: Math.floor(Math.random() * 100),
      confidence: 85 + Math.floor(Math.random() * 15),
    };

    if (isHash) {
      // File analysis for hashes
      baseAnalysis.fileInfo = {
        name: 'parafin.bin',
        size: Math.floor(Math.random() * 2000000) + 100000,
        type: 'PE32 executable (GUI) Intel 80386, for MS Windows',
        md5: item.ioc.length === 32 ? item.ioc : 'cf6eb0ac5cd413d93bef4f3b',
        sha1: item.ioc.length === 40 ? item.ioc : 'bd25faa78702d876d8dfa01a1d88a73d6a3d3b4f',
        sha256: item.ioc.length === 64 ? item.ioc : 'bd34faa78702d876d8dfa01a1d88a73d6a3d3b4fa1d2f5c8b9e0fd7e6c4a2b3c1',
        uploadDate: new Date().toISOString(),
      };

      baseAnalysis.threatClassification = {
        primaryType: 'Trojan',
        family: 'Generic.DX',
        severity: 'High',
        tags: ['malware', 'backdoor', 'stealer', 'keylogger']
      };

      baseAnalysis.vtResults = {
        malicious: 31,
        suspicious: 8,
        harmless: 53,
        undetected: 0,
        engines: [
          { name: 'Rising', verdict: 'Trojan.HijackLoader', status: 'detected', lastUpdate: '2025-01-30' },
          { name: 'Trellix (Fire Eye)', verdict: 'Generic.DX', status: 'detected', lastUpdate: '2025-01-30' },
          { name: 'Skyhigh (SWG)', verdict: 'Trojan.HijackLoader.RW', status: 'detected', lastUpdate: '2025-01-30' },
          { name: 'AhnLab-V3', verdict: 'Undetected', status: 'clean', lastUpdate: '2025-01-30' },
          { name: 'ALYac', verdict: 'Undetected', status: 'clean', lastUpdate: '2025-01-30' },
          { name: 'Arcabit', verdict: 'Undetected', status: 'clean', lastUpdate: '2025-01-30' },
          { name: 'Acronis', verdict: 'Undetected', status: 'clean', lastUpdate: '2025-01-30' },
          { name: 'Antiy-AVL', verdict: 'Undetected', status: 'clean', lastUpdate: '2025-01-30' },
          { name: 'Avast', verdict: 'Undetected', status: 'clean', lastUpdate: '2025-01-30' },
          { name: 'BitDefender', verdict: 'Trojan.Generic.KD.70080771', status: 'detected', lastUpdate: '2025-01-30' },
          { name: 'ClamAV', verdict: 'Undetected', status: 'clean', lastUpdate: '2025-01-30' },
          { name: 'ESET-NOD32', verdict: 'Win32/HijackLoader.MAD', status: 'detected', lastUpdate: '2025-01-30' },
        ]
      };

      baseAnalysis.behaviorAnalysis = {
        fileCreation: Math.floor(Math.random() * 20) + 5,
        registryModification: Math.floor(Math.random() * 15) + 3,
        networkCommunication: Math.floor(Math.random() * 10) + 2,
        processInjection: Math.floor(Math.random() * 5) + 1,
        serviceInstallation: Math.floor(Math.random() * 3) + 1,
      };
    }

    if (isIP) {
      // Network analysis for IPs
      baseAnalysis.threatTrends = Array.from({ length: 24 }, (_, i) => ({
        time: String(i).padStart(2, '0') + ':00',
        threats: Math.floor(Math.random() * 30) + 5,
      }));

      baseAnalysis.vtResults = {
        malicious: Math.floor(Math.random() * 20) + 10,
        suspicious: Math.floor(Math.random() * 15) + 5,
        harmless: Math.floor(Math.random() * 30) + 20,
        undetected: Math.floor(Math.random() * 10),
        engines: [
          { name: 'Fortinet', verdict: 'Malicious', status: 'detected', lastUpdate: '2025-01-30' },
          { name: 'Sophos', verdict: 'Suspicious', status: 'detected', lastUpdate: '2025-01-30' },
          { name: 'Kaspersky', verdict: 'Clean', status: 'clean', lastUpdate: '2025-01-30' },
          { name: 'Symantec', verdict: 'Malicious', status: 'detected', lastUpdate: '2025-01-30' },
        ]
      };
    }

    return baseAnalysis;
  };

  const sampleIOCs = [
    '8.8.8.8',
    'google.com',
    'http://example.com',
    '44d88612fea8a8f36de82e1278abb02f',
  ];

  const insertSampleData = () => {
    form.setValue('iocs', sampleIOCs.join('\n'));
    form.setValue('label', 'Sample Analysis');
  };

  const getVerdictBadge = (verdict: string) => {
    const variants = {
      malicious: 'destructive',
      suspicious: 'secondary', 
      harmless: 'default',
      undetected: 'outline',
      unknown: 'outline',
    } as const;
    
    return (
      <Badge variant={variants[verdict as keyof typeof variants] || 'outline'}>
        {verdict}
      </Badge>
    );
  };

  const getVerdictIcon = (verdict: string) => {
    switch (verdict) {
      case 'malicious':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      case 'suspicious':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'harmless':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      default:
        return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  // Chart color schemes
  const COLORS = ['#ef4444', '#f97316', '#22c55e', '#6b7280', '#8b5cf6'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Threat Hunting</h1>
          <p className="text-muted-foreground">Advanced threat intelligence with real-time analysis</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="text-right">
            <div className="text-2xl font-bold text-red-500">31</div>
            <div className="text-sm text-muted-foreground">Active Threats</div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-green-500">98.7%</div>
            <div className="text-sm text-muted-foreground">Detection Rate</div>
          </div>
        </div>
      </div>

      {/* Critical Threat Alert */}
      {detailedAnalysis && detailedAnalysis.riskScore > 70 && (
        <div className="bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <AlertTriangle className="h-6 w-6 text-red-500" />
              <div>
                <h3 className="font-semibold text-red-500">CRITICAL THREAT DETECTED</h3>
                <p className="text-sm text-red-400">High-risk malware identified with {detailedAnalysis.vtResults?.malicious || 0} engine detections</p>
              </div>
            </div>
            <Button variant="destructive" size="sm">
              IMMEDIATE ACTION REQUIRED
            </Button>
          </div>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Analysis Form */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Search className="h-5 w-5" />
              <span>IOC Intelligence Search</span>
            </CardTitle>
            <CardDescription>
              Enter IOCs (Hash, Domain, IP, URL) one per line for comprehensive threat analysis
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="iocs"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Enter IOCs (Hash, Domain, IP, URL)</FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder="bd34faa78702d876d8dfa01a1d88a73d6a3d3b4f (full hash)&#10;192.168.1.100&#10;malware.example.com&#10;http://suspicious-site.com"
                          className="min-h-[120px] font-mono text-sm bg-slate-50 dark:bg-slate-800"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                      <div className="text-xs text-muted-foreground">
                        Try searching: <span className="font-mono bg-slate-100 dark:bg-slate-800 px-1 py-0.5 rounded text-blue-600">bd34faa78702d876d8dfa01a1d88a73d6a3d3b4f</span> (Sample test)
                      </div>
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="label"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Case Label (Optional)</FormLabel>
                      <FormControl>
                        <Input placeholder="Investigation 2024-001" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <div className="flex space-x-2">
                  <Button type="submit" disabled={isSubmitting} className="flex-1 bg-blue-600 hover:bg-blue-700">
                    {isSubmitting ? (
                      <>
                        <Activity className="h-4 w-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Search className="h-4 w-4 mr-2" />
                        Start Analysis
                      </>
                    )}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={insertSampleData}
                  >
                    <Upload className="h-4 w-4 mr-2" />
                    Sample
                  </Button>
                </div>

                {isSubmitting && (
                  <div className="space-y-2">
                    <Progress value={progress} className="w-full" />
                    <p className="text-sm text-muted-foreground text-center">
                      Processing IOCs... {progress}%
                    </p>
                  </div>
                )}
              </form>
            </Form>
          </CardContent>
        </Card>

        {/* Quick Results */}
        <Card>
          <CardHeader>
            <CardTitle>Analysis Overview</CardTitle>
            <CardDescription>
              {results ? 
                `Processed ${results.total} IOCs (${results.created} new, ${results.fromCache} cached)` :
                'Results will appear here after analysis'
              }
            </CardDescription>
          </CardHeader>
          <CardContent>
            {results ? (
              <div className="space-y-4">
                {/* Summary Stats */}
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                    <div className="text-2xl font-bold text-green-500">{results.created}</div>
                    <div className="text-sm text-muted-foreground">New</div>
                  </div>
                  <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                    <div className="text-2xl font-bold text-blue-500">{results.fromCache}</div>
                    <div className="text-sm text-muted-foreground">Cached</div>
                  </div>
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <div className="text-2xl font-bold text-red-500">{results.errors.length}</div>
                    <div className="text-sm text-muted-foreground">Errors</div>
                  </div>
                </div>

                {/* Results List */}
                <div className="space-y-2">
                  {results.items.map((item) => (
                    <div key={item._id} className="flex items-center justify-between p-3 rounded-lg border hover:bg-slate-50 dark:hover:bg-slate-800">
                      <div className="flex items-center space-x-3">
                        {getVerdictIcon(item.verdict)}
                        <div>
                          <p className="font-medium font-mono text-sm">{item.ioc.length > 40 ? item.ioc.substring(0, 40) + '...' : item.ioc}</p>
                          <p className="text-xs text-muted-foreground uppercase">{item.type}</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        {getVerdictBadge(item.verdict)}
                        <Button size="sm" variant="ghost">
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Submit IOCs to see analysis results</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Detailed Analysis Results */}
      {detailedAnalysis && (
        <div className="space-y-6">
          {/* File Information & Threat Classification */}
          {detailedAnalysis.fileInfo && (
            <div className="grid gap-6 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <FileText className="h-5 w-5" />
                    <span>File Information</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm font-medium">File Name:</span>
                      <span className="text-sm font-mono">{detailedAnalysis.fileInfo.name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm font-medium">Size:</span>
                      <span className="text-sm">{(detailedAnalysis.fileInfo.size / 1024 / 1024).toFixed(2)} MB ({detailedAnalysis.fileInfo.size.toLocaleString()} bytes)</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm font-medium">File Type:</span>
                      <span className="text-sm">{detailedAnalysis.fileInfo.type}</span>
                    </div>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-sm font-medium">MD5:</span>
                        <span className="text-xs font-mono bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded">{detailedAnalysis.fileInfo.md5}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm font-medium">SHA1:</span>
                        <span className="text-xs font-mono bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded">{detailedAnalysis.fileInfo.sha1}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm font-medium">SHA256:</span>
                        <span className="text-xs font-mono bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded">{detailedAnalysis.fileInfo.sha256.substring(0, 32)}...</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {detailedAnalysis.threatClassification && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Shield className="h-5 w-5" />
                      <span>Threat Classification</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-sm font-medium">Primary Type:</span>
                        <Badge variant="destructive">{detailedAnalysis.threatClassification.primaryType}</Badge>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm font-medium">Family:</span>
                        <span className="text-sm font-mono">{detailedAnalysis.threatClassification.family}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm font-medium">Severity:</span>
                        <Badge variant="destructive">{detailedAnalysis.threatClassification.severity}</Badge>
                      </div>
                      <div className="space-y-2">
                        <span className="text-sm font-medium">Tags:</span>
                        <div className="flex flex-wrap gap-1">
                          {detailedAnalysis.threatClassification.tags.map((tag, index) => (
                            <Badge key={index} variant="secondary" className="text-xs">{tag}</Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {/* Analysis Results with Charts */}
          <div className="grid gap-6 lg:grid-cols-3">
            {/* Community Score */}
            <Card>
              <CardHeader>
                <CardTitle className="text-center">Community Score</CardTitle>
              </CardHeader>
              <CardContent className="flex items-center justify-center">
                <div className="w-32 h-32">
                  <CircularProgressbar
                    value={detailedAnalysis.riskScore}
                    text={`${detailedAnalysis.riskScore}/100`}
                    styles={buildStyles({
                      textColor: detailedAnalysis.riskScore > 70 ? '#ef4444' : detailedAnalysis.riskScore > 40 ? '#f59e0b' : '#22c55e',
                      pathColor: detailedAnalysis.riskScore > 70 ? '#ef4444' : detailedAnalysis.riskScore > 40 ? '#f59e0b' : '#22c55e',
                      trailColor: '#e5e7eb',
                    })}
                  />
                </div>
              </CardContent>
            </Card>

            {/* File Size */}
            <Card>
              <CardHeader>
                <CardTitle className="text-center">Size</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center justify-center">
                <div className="text-3xl font-bold text-blue-500">
                  {detailedAnalysis.fileInfo ? `${(detailedAnalysis.fileInfo.size / 1024 / 1024).toFixed(1)} MB` : 'N/A'}
                </div>
                <div className="text-sm text-muted-foreground">File Size</div>
              </CardContent>
            </Card>

            {/* Last Analysis Date */}
            <Card>
              <CardHeader>
                <CardTitle className="text-center">Last Analysis Date</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center justify-center">
                <div className="text-2xl font-bold text-purple-500">30 hours ago</div>
                <div className="text-sm text-muted-foreground">Last Analysis Date</div>
              </CardContent>
            </Card>
          </div>

          {/* Security Vendors Analysis & Charts */}
          {detailedAnalysis.vtResults && (
            <div className="space-y-6">
              {/* Threat Detection Overview */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Activity className="h-5 w-5" />
                    <span>Threat Detection Overview</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-6 lg:grid-cols-2">
                    {/* Detection Pie Chart */}
                    <div className="space-y-4">
                      <h4 className="font-medium">Detection Distribution</h4>
                      <ResponsiveContainer width="100%" height={300}>
                        <PieChart>
                          <Pie
                            data={[
                              { name: 'Malicious', value: detailedAnalysis.vtResults.malicious, color: '#ef4444' },
                              { name: 'Suspicious', value: detailedAnalysis.vtResults.suspicious, color: '#f59e0b' },
                              { name: 'Harmless', value: detailedAnalysis.vtResults.harmless, color: '#22c55e' },
                              { name: 'Undetected', value: detailedAnalysis.vtResults.undetected, color: '#6b7280' },
                            ]}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={120}
                            paddingAngle={2}
                            dataKey="value"
                          >
                            {[
                              { name: 'Malicious', value: detailedAnalysis.vtResults.malicious, color: '#ef4444' },
                              { name: 'Suspicious', value: detailedAnalysis.vtResults.suspicious, color: '#f59e0b' },
                              { name: 'Harmless', value: detailedAnalysis.vtResults.harmless, color: '#22c55e' },
                              { name: 'Undetected', value: detailedAnalysis.vtResults.undetected, color: '#6b7280' },
                            ].map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>

                    {/* 24H Threat Trends */}
                    {detailedAnalysis.threatTrends && (
                      <div className="space-y-4">
                        <h4 className="font-medium">24H Threat Trends</h4>
                        <ResponsiveContainer width="100%" height={300}>
                          <AreaChart data={detailedAnalysis.threatTrends}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="time" />
                            <YAxis />
                            <Tooltip />
                            <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="#ef4444" fillOpacity={0.3} />
                          </AreaChart>
                        </ResponsiveContainer>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Security Vendors Analysis */}
              <Card>
                <CardHeader>
                  <CardTitle>Security vendors' analysis</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {detailedAnalysis.vtResults.engines.map((engine, index) => (
                      <div key={index} className="flex items-center justify-between p-3 rounded-lg border hover:bg-slate-50 dark:hover:bg-slate-800">
                        <div className="flex items-center space-x-3">
                          <div className={`w-2 h-2 rounded-full ${engine.status === 'detected' ? 'bg-red-500' : 'bg-green-500'}`} />
                          <span className="font-medium">{engine.name}</span>
                        </div>
                        <div className="flex items-center space-x-4">
                          <span className={`text-sm ${engine.status === 'detected' ? 'text-red-500' : 'text-green-500'}`}>
                            {engine.verdict}
                          </span>
                          <span className="text-xs text-muted-foreground">{engine.lastUpdate}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Behavior Analysis */}
              {detailedAnalysis.behaviorAnalysis && (
                <Card>
                  <CardHeader>
                    <CardTitle>Sandbox Analysis</CardTitle>
                    <CardDescription>Behavioral analysis from dynamic execution</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {Object.entries(detailedAnalysis.behaviorAnalysis).map(([key, value]) => (
                        <div key={key} className="flex items-center justify-between p-3 rounded-lg border">
                          <span className="font-medium capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                          <div className="flex items-center space-x-3">
                            <span className={`font-bold ${value > 10 ? 'text-red-500' : value > 5 ? 'text-yellow-500' : 'text-green-500'}`}>
                              {value}
                            </span>
                            <Badge variant={value > 10 ? 'destructive' : value > 5 ? 'secondary' : 'default'}>
                              {value > 10 ? 'Critical' : value > 5 ? 'High' : 'Medium'}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Engine Performance Analysis */}
              <Card>
                <CardHeader>
                  <CardTitle>Engine Performance Analysis</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={400}>
                    <BarChart data={detailedAnalysis.vtResults.engines.slice(0, 5).map(engine => ({
                      name: engine.name,
                      detected: engine.status === 'detected' ? 1 : 0,
                      clean: engine.status === 'clean' ? 1 : 0
                    }))}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" />
                      <YAxis />
                      <Tooltip />
                      <Bar dataKey="detected" fill="#ef4444" name="Detected" />
                      <Bar dataKey="clean" fill="#22c55e" name="Clean" />
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Threat Vector Analysis */}
          <Card>
            <CardHeader>
              <CardTitle>Threat Vector Analysis</CardTitle>
              <CardDescription>High Activity threats categorized by type</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-5 gap-4">
                {[
                  { name: 'Trojan', count: 12, color: '#ef4444' },
                  { name: 'Malware', count: 8, color: '#dc2626' },
                  { name: 'Ransomware', count: 5, color: '#991b1b' },
                  { name: 'Adware', count: 3, color: '#f59e0b' },
                  { name: 'Spyware', count: 6, color: '#f97316' }
                ].map((threat) => (
                  <div key={threat.name} className="text-center p-4 rounded-lg border">
                    <div className="text-2xl font-bold mb-2" style={{ color: threat.color }}>
                      {threat.count}
                    </div>
                    <div className="text-sm font-medium">{threat.name}</div>
                    <div className="text-xs text-muted-foreground">Detections</div>
                    <div className="mt-2 h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div 
                        className="h-full rounded-full" 
                        style={{ 
                          backgroundColor: threat.color,
                          width: `${Math.min((threat.count / 12) * 100, 100)}%`
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
