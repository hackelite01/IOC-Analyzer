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
import { Search, Upload, CheckCircle, AlertCircle, Clock, Copy, Shield, TrendingUp, FileText, Activity, AlertTriangle, ChevronDown } from 'lucide-react';
import { toast } from 'sonner';

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
    tlsh: string;
    magic: string;
    uploadDate: string;
    firstSeen: string;
    lastAnalysis: string;
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
  sandboxAnalysis?: {
    status: string;
    runtime: string;
    environment: string;
    behaviorAnalysis: {
      fileCreation: { count: number; severity: string };
      registryModification: { count: number; severity: string };
      networkCommunication: { count: number; severity: string };
      processInjection: { count: number; severity: string };
      serviceInstallation: { count: number; severity: string };
    };
  };
  riskScore: number;
  confidence: number;
  lastUpdated?: string;
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
  const [activeTab, setActiveTab] = useState<'detection' | 'details' | 'relations' | 'behavior'>('detection');
  const [iocResultsExpanded, setIocResultsExpanded] = useState(true);
  const [resultsTab, setResultsTab] = useState<'ioc' | 'file'>('ioc');
  const [loadingRealTimeData, setLoadingRealTimeData] = useState(false);

  const form = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      iocs: '',
      label: '',
    },
  });

  const fetchRealTimeVirusTotalData = async (ioc: string) => {
    setLoadingRealTimeData(true);
    try {
      const response = await fetch('/api/virustotal', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ioc }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        
        if (response.status === 401 && errorData.requiresApiKey) {
          toast.error('VirusTotal API key required. Please check your .env.local file.');
          throw new Error('VirusTotal API key required');
        }
        
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Failed to fetch real-time VirusTotal data:', error);
      toast.error('Failed to fetch real-time analysis data');
      return null;
    } finally {
      setLoadingRealTimeData(false);
    }
  };

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
      
      // Fetch real-time detailed analysis for the first IOC (or first hash)
      if (result.items && result.items.length > 0) {
        const firstHashIOC = result.items.find((item: SubmissionResult) => item.type === 'hash') || result.items[0];
        toast.success('Fetching real-time VirusTotal analysis...');
        
        const realTimeData = await fetchRealTimeVirusTotalData(firstHashIOC.ioc);
        if (realTimeData) {
          setDetailedAnalysis(realTimeData);
          toast.success('Real-time analysis data loaded successfully!');
        }
      }
      
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
    
    const baseAnalysis: DetailedAnalysis = {
      riskScore: 31,
      confidence: 85 + Math.floor(Math.random() * 15),
    };

    if (isHash) {
      baseAnalysis.fileInfo = {
        name: 'parafin.bin',
        size: 1445179,
        type: 'PE32 executable (GUI) Intel 80386, for MS Windows',
        md5: 'cf6eb0ac5cd413d93bef403f',
        sha1: 'caa648e83b0068ec6fe05af2aca59631f',
        sha256: '8d24d4e72b7b22017c6d6e7b1a2dc1a1ead63b97b58114c02c221aa86dd9d00c',
        tlsh: 'T150C232C0D3C0AF2F8938383074594T15952329G522A0CD619G0AC0A1684',
        magic: 'PE32 executable (GUI) Intel 80386, for MS Windows',
        uploadDate: new Date().toISOString(),
        firstSeen: '2025-01-29 15:18:00 UTC',
        lastAnalysis: '30 hours ago'
      };

      baseAnalysis.vtResults = {
        malicious: 31,
        suspicious: 8,
        harmless: 53,
        undetected: 0,
        engines: [
          { name: 'Rising', verdict: 'Trojan.HijackLoader', status: 'detected', lastUpdate: '2025-01-30' },
          { name: 'Trellix ENS', verdict: 'Trojan/HijackLoader.RW', status: 'detected', lastUpdate: '2025-01-30' },
          { name: 'Skyhigh', verdict: 'Trojan.HijackLoader.RW', status: 'detected', lastUpdate: '2025-01-30' },
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
    }

    return baseAnalysis;
  };

  const sampleIOCs = [
    '8.8.8.8',
    'google.com',
    'http://example.com',
    '8d24d4e72b7b22017c6d6e7b1a2dc1a1ead63b97b58114c02c221aa86dd9d00c',
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
                          placeholder="8d24d4e72b7b22017c6d6e7b1a2dc1a1ead63b97b58114c02c221aa86dd9d00c&#10;192.168.1.100&#10;malware.example.com&#10;http://suspicious-site.com"
                          className="min-h-[120px] font-mono text-sm bg-slate-50 dark:bg-slate-800"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                      <div className="text-xs text-muted-foreground">
                        Try searching: <span className="font-mono bg-slate-100 dark:bg-slate-800 px-1 py-0.5 rounded text-blue-600">8d24d4e72b7b22017c6d6e7b1a2dc1a1ead63b97b58114c02c221aa86dd9d00c</span> (Sample test)
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
                        Hunt
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

        {/* Results Tabs */}
        {results ? (
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Analysis Results</CardTitle>
                  <CardDescription>
                    Processed {results.total} IOCs ({results.created} new, {results.fromCache} cached)
                  </CardDescription>
                </div>
                {/* Tab Buttons */}
                <div className="flex space-x-2">
                  <Button 
                    variant={resultsTab === 'ioc' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setResultsTab('ioc')}
                    className={resultsTab === 'ioc' ? 'bg-blue-600 hover:bg-blue-700' : ''}
                  >
                    <Search className="h-4 w-4 mr-2" />
                    IOC Results
                  </Button>
                  <Button 
                    variant={resultsTab === 'file' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setResultsTab('file')}
                    className={resultsTab === 'file' ? 'bg-purple-600 hover:bg-purple-700' : ''}
                  >
                    <FileText className="h-4 w-4 mr-2" />
                    File Analysis Results
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {resultsTab === 'ioc' ? (
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
                /* File Analysis Results Content */
                <div className="space-y-6">
                  {loadingRealTimeData ? (
                    <div className="flex items-center justify-center py-12">
                      <div className="text-center space-y-4">
                        <Activity className="h-8 w-8 animate-spin mx-auto text-blue-600" />
                        <div className="space-y-2">
                          <p className="text-lg font-medium">Fetching Real-time VirusTotal Data</p>
                          <p className="text-sm text-muted-foreground">Connecting to VirusTotal API...</p>
                        </div>
                      </div>
                    </div>
                  ) : detailedAnalysis ? (
                    <>
                      {/* Real-time Status Banner */}
                      <div className="bg-gradient-to-r from-green-500/10 to-blue-500/10 border border-green-500/20 rounded-lg p-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                            <div>
                              <h3 className="font-semibold text-green-600">LIVE VIRUSTOTAL DATA</h3>
                              <p className="text-sm text-green-600/80">
                                Last updated: {detailedAnalysis.lastUpdated ? 
                                  new Date(detailedAnalysis.lastUpdated).toLocaleString() : 
                                  'Just now'
                                }
                              </p>
                            </div>
                          </div>
                          <Button 
                            variant="outline" 
                            size="sm" 
                            onClick={async () => {
                              if (results?.items && results.items.length > 0) {
                                const firstHashIOC = results.items.find((item: SubmissionResult) => item.type === 'hash') || results.items[0];
                                const newData = await fetchRealTimeVirusTotalData(firstHashIOC.ioc);
                                if (newData) {
                                  setDetailedAnalysis(newData);
                                  toast.success('Data refreshed with latest VirusTotal results!');
                                }
                              }
                            }}
                            disabled={loadingRealTimeData}
                          >
                            {loadingRealTimeData ? (
                              <Activity className="h-4 w-4 mr-2 animate-spin" />
                            ) : (
                              <Activity className="h-4 w-4 mr-2" />
                            )}
                            Refresh Real-time Data
                          </Button>
                        </div>
                      </div>
                      {detailedAnalysis.vtResults && detailedAnalysis.vtResults.malicious > 5 && (
                        <div className="bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-lg p-4">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-3">
                              <AlertTriangle className="h-6 w-6 text-red-500" />
                              <div>
                                <h3 className="font-semibold text-red-500">CRITICAL THREAT DETECTED</h3>
                                <p className="text-sm text-red-400">High-risk malware identified with {detailedAnalysis.vtResults.malicious} VirusTotal engine detections</p>
                              </div>
                            </div>
                            <Button variant="destructive" size="sm">
                              IMMEDIATE ACTION REQUIRED
                            </Button>
                          </div>
                        </div>
                      )}

                      {/* Comprehensive File Analysis Header */}
                      <div className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 rounded-lg p-6">
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center space-x-3">
                            <Activity className="h-6 w-6 text-blue-600" />
                            <h3 className="text-lg font-semibold">Comprehensive File Analysis</h3>
                            <Badge variant="secondary" className="bg-green-100 text-green-600 border-green-200">
                              Live Analysis
                            </Badge>
                          </div>
                        </div>
                        
                        {/* Analysis Stats */}
                        <div className="grid grid-cols-5 gap-4 text-center">
                          <div>
                            <div className="text-2xl font-bold text-blue-600">1,445,179</div>
                            <div className="text-sm text-gray-600">File Size (bytes)</div>
                          </div>
                          <div>
                            <div className="text-2xl font-bold text-red-600">{detailedAnalysis.vtResults?.malicious || 31}</div>
                            <div className="text-sm text-gray-600">Threats Detected</div>
                          </div>
                          <div>
                            <div className="text-2xl font-bold text-green-600">{detailedAnalysis.vtResults?.harmless || 53}</div>
                            <div className="text-sm text-gray-600">Clean Results</div>
                          </div>
                          <div>
                            <div className="text-2xl font-bold text-yellow-600">2.3s</div>
                            <div className="text-sm text-gray-600">Analysis Time</div>
                          </div>
                          <div>
                            <div className="text-2xl font-bold text-purple-600">{detailedAnalysis.confidence}%</div>
                            <div className="text-sm text-gray-600">Confidence</div>
                          </div>
                        </div>
                      </div>

                      {/* Main Analysis Grid */}
                      <div className="grid gap-6 lg:grid-cols-3">
                        {/* File Information */}
                        <Card>
                          <CardHeader className="pb-3">
                            <CardTitle className="flex items-center space-x-2">
                              <FileText className="h-4 w-4" />
                              <span>File Information</span>
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">File Name</div>
                              <div className="text-sm font-mono">{detailedAnalysis.fileInfo?.name || 'parafin.bin'}</div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Size</div>
                              <div className="text-sm">1.38 MB (1,445,179 bytes)</div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Type</div>
                              <div className="text-sm">PE32 executable (GUI) Intel 80386, for MS Windows</div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">MD5</div>
                              <div className="text-xs font-mono break-all">cf6eb0ac5cd413d93bef403f</div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">SHA256</div>
                              <div className="text-xs font-mono break-all">8d24d4e72b7b22017c6d6e7b1a2dc1a1ead63b97b58114c02c221aa86dd9d00c</div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">First Seen</div>
                              <div className="text-sm">2025-01-29 15:18:00 UTC</div>
                            </div>
                          </CardContent>
                        </Card>

                        {/* Threat Classification */}
                        <Card>
                          <CardHeader className="pb-3">
                            <CardTitle className="flex items-center space-x-2">
                              <AlertTriangle className="h-4 w-4" />
                              <span>Threat Classification</span>
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Primary Type</div>
                              <div className="text-sm">
                                <Badge variant="destructive">{detailedAnalysis.threatClassification?.primaryType || 'Unknown'}</Badge>
                              </div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Family</div>
                              <div className="text-sm">
                                <Badge variant="secondary" className="bg-orange-100 text-orange-600">{detailedAnalysis.threatClassification?.family || 'Unknown'}</Badge>
                              </div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Severity</div>
                              <div className="text-sm">
                                <Badge 
                                  variant={detailedAnalysis.threatClassification?.severity === 'High' ? 'destructive' : 
                                          detailedAnalysis.threatClassification?.severity === 'Medium' ? 'secondary' : 'outline'}
                                  className={detailedAnalysis.threatClassification?.severity === 'Medium' ? 'bg-yellow-100 text-yellow-600' : ''}
                                >
                                  {detailedAnalysis.threatClassification?.severity || 'Unknown'}
                                </Badge>
                              </div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">MITRE ATT&CK Tactics</div>
                              <div className="flex flex-wrap gap-1 mt-1">
                                <Badge variant="outline" className="text-xs">Initial Access</Badge>
                                <Badge variant="outline" className="text-xs">Defense Evasion</Badge>
                                <Badge variant="outline" className="text-xs">Persistence</Badge>
                              </div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Tags</div>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {detailedAnalysis.threatClassification?.tags && detailedAnalysis.threatClassification.tags.length > 0 ? 
                                  detailedAnalysis.threatClassification.tags.map((tag, index) => (
                                    <Badge key={index} variant="outline" className="text-xs">{tag}</Badge>
                                  )) :
                                  <>
                                    <Badge variant="outline" className="text-xs">unknown</Badge>
                                  </>
                                }
                              </div>
                            </div>
                          </CardContent>
                        </Card>

                        {/* Sandbox Analysis */}
                        <Card>
                          <CardHeader className="pb-3">
                            <CardTitle className="flex items-center space-x-2">
                              <Activity className="h-4 w-4" />
                              <span>Sandbox Analysis</span>
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Status</div>
                              <div className="text-sm">
                                <Badge variant="secondary" className="bg-green-100 text-green-600">
                                  {detailedAnalysis.sandboxAnalysis?.status || 'Analyzed'}
                                </Badge>
                              </div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Runtime</div>
                              <div className="text-sm">{detailedAnalysis.sandboxAnalysis?.runtime || '180s'}</div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Environment</div>
                              <div className="text-sm">{detailedAnalysis.sandboxAnalysis?.environment || 'Windows 10 x64'}</div>
                            </div>
                            <div>
                              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Behavioral Analysis</div>
                              <div className="space-y-2 mt-2">
                                <div className="flex justify-between items-center">
                                  <span className="text-xs">File Creation</span>
                                  <div className="flex items-center space-x-1">
                                    <span className="text-xs">{detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.fileCreation.count || 7}</span>
                                    <Badge 
                                      variant={detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.fileCreation.severity === 'high' ? 'destructive' : 'secondary'} 
                                      className={`text-xs ${
                                        detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.fileCreation.severity === 'high' 
                                          ? '' 
                                          : detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.fileCreation.severity === 'medium'
                                          ? 'bg-yellow-100 text-yellow-600'
                                          : 'bg-green-100 text-green-600'
                                      }`}
                                    >
                                      {detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.fileCreation.severity || 'medium'}
                                    </Badge>
                                  </div>
                                </div>
                                <div className="flex justify-between items-center">
                                  <span className="text-xs">Registry Modification</span>
                                  <div className="flex items-center space-x-1">
                                    <span className="text-xs">{detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.registryModification.count || 12}</span>
                                    <Badge 
                                      variant={detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.registryModification.severity === 'high' ? 'destructive' : 'secondary'} 
                                      className={`text-xs ${
                                        detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.registryModification.severity === 'high' 
                                          ? '' 
                                          : detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.registryModification.severity === 'medium'
                                          ? 'bg-yellow-100 text-yellow-600'
                                          : 'bg-green-100 text-green-600'
                                      }`}
                                    >
                                      {detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.registryModification.severity || 'high'}
                                    </Badge>
                                  </div>
                                </div>
                                <div className="flex justify-between items-center">
                                  <span className="text-xs">Network Communication</span>
                                  <div className="flex items-center space-x-1">
                                    <span className="text-xs">{detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.networkCommunication.count || 3}</span>
                                    <Badge 
                                      variant={detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.networkCommunication.severity === 'high' ? 'destructive' : 'secondary'} 
                                      className={`text-xs ${
                                        detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.networkCommunication.severity === 'high' 
                                          ? '' 
                                          : detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.networkCommunication.severity === 'medium'
                                          ? 'bg-yellow-100 text-yellow-600'
                                          : 'bg-green-100 text-green-600'
                                      }`}
                                    >
                                      {detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.networkCommunication.severity || 'high'}
                                    </Badge>
                                  </div>
                                </div>
                                <div className="flex justify-between items-center">
                                  <span className="text-xs">Process Injection</span>
                                  <div className="flex items-center space-x-1">
                                    <span className="text-xs">{detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.processInjection.count || 2}</span>
                                    <Badge 
                                      variant={detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.processInjection.severity === 'critical' ? 'destructive' : 'secondary'} 
                                      className={`text-xs ${
                                        detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.processInjection.severity === 'critical' 
                                          ? 'bg-red-600 text-white' 
                                          : detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.processInjection.severity === 'high'
                                          ? ''
                                          : detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.processInjection.severity === 'medium'
                                          ? 'bg-yellow-100 text-yellow-600'
                                          : 'bg-green-100 text-green-600'
                                      }`}
                                    >
                                      {detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.processInjection.severity || 'critical'}
                                    </Badge>
                                  </div>
                                </div>
                                <div className="flex justify-between items-center">
                                  <span className="text-xs">Service Installation</span>
                                  <div className="flex items-center space-x-1">
                                    <span className="text-xs">{detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.serviceInstallation.count || 1}</span>
                                    <Badge 
                                      variant={detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.serviceInstallation.severity === 'high' ? 'destructive' : 'secondary'} 
                                      className={`text-xs ${
                                        detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.serviceInstallation.severity === 'high' 
                                          ? '' 
                                          : detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.serviceInstallation.severity === 'medium'
                                          ? 'bg-yellow-100 text-yellow-600'
                                          : 'bg-green-100 text-green-600'
                                      }`}
                                    >
                                      {detailedAnalysis.sandboxAnalysis?.behaviorAnalysis.serviceInstallation.severity || 'high'}
                                    </Badge>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      </div>

                      {/* Detailed Antivirus Engine Results */}
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center space-x-2">
                            <Shield className="h-5 w-5" />
                            <span>Detailed Antivirus Engine Results</span>
                            <svg className="h-4 w-4 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                            </svg>
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="overflow-x-auto">
                            <table className="w-full">
                              <thead>
                                <tr className="border-b">
                                  <th className="text-left py-3 px-2 text-sm font-medium">Vendor</th>
                                  <th className="text-left py-3 px-2 text-sm font-medium">Status</th>
                                  <th className="text-left py-3 px-2 text-sm font-medium">Verdict</th>
                                  <th className="text-right py-3 px-2 text-sm font-medium">Last Update</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y">
                                {detailedAnalysis.vtResults?.engines.map((engine, index) => (
                                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                                    <td className="py-3 px-2">
                                      <div className="flex items-center space-x-2">
                                        <div className={`w-2 h-2 rounded-full ${
                                          engine.status === 'detected' ? 'bg-red-500' : 'bg-green-500'
                                        }`} />
                                        <span className="text-sm font-medium">{engine.name}</span>
                                      </div>
                                    </td>
                                    <td className="py-3 px-2">
                                      <Badge 
                                        variant={engine.status === 'detected' ? 'destructive' : 'secondary'}
                                        className={engine.status === 'detected' ? '' : 'bg-green-100 text-green-600'}
                                      >
                                        {engine.status}
                                      </Badge>
                                    </td>
                                    <td className="py-3 px-2">
                                      <span className={`text-sm font-medium ${
                                        engine.status === 'detected' ? 'text-red-600' : 'text-green-600'
                                      }`}>
                                        {engine.verdict}
                                      </span>
                                    </td>
                                    <td className="py-3 px-2 text-right">
                                      <span className="text-sm text-gray-500">{engine.lastUpdate}</span>
                                    </td>
                                  </tr>
                                )) || []}
                              </tbody>
                            </table>
                          </div>
                        </CardContent>
                      </Card>

                      {/* Engine Performance Analysis */}
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center space-x-2">
                            <TrendingUp className="h-5 w-5" />
                            <span>Engine Performance Analysis</span>
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-4">
                            <div className="grid grid-cols-5 gap-4">
                              {['Rising', 'Trellix', 'Skyhigh', 'BitDefender', 'ESET'].map((engine, index) => {
                                const accuracy = [95, 88, 94, 87, 96][index];
                                const detections = [85, 78, 91, 75, 93][index];
                                
                                return (
                                  <div key={engine} className="text-center">
                                    <div className="mb-2">
                                      <div className="text-sm font-medium">{engine}</div>
                                    </div>
                                    <div 
                                      className="relative h-32 w-16 mx-auto group cursor-pointer"
                                    >
                                      {/* Blue bar (Accuracy) */}
                                      <div 
                                        className="absolute bottom-0 w-8 bg-blue-500 rounded-t transition-all duration-200 hover:bg-blue-400"
                                        style={{ height: `${accuracy}%` }}
                                      />
                                      {/* Green bar (Detections) */}
                                      <div 
                                        className="absolute bottom-0 right-0 w-8 bg-green-500 rounded-t transition-all duration-200 hover:bg-green-400"
                                        style={{ height: `${detections}%` }}
                                      />
                                      
                                      {/* Hover Tooltip */}
                                      <div className="absolute -top-14 left-1/2 transform -translate-x-1/2 bg-black/90 text-white text-xs px-3 py-2 rounded shadow-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 z-10 whitespace-nowrap">
                                        <div>Accuracy: {accuracy}%</div>
                                        <div>Detections: {detections}</div>
                                        <div className="absolute top-full left-1/2 transform -translate-x-1/2 w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-black/90"></div>
                                      </div>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                            <div className="flex justify-center space-x-6 text-xs">
                              <div className="flex items-center space-x-2">
                                <div className="w-3 h-3 bg-blue-500 rounded"></div>
                                <span>Accuracy %</span>
                              </div>
                              <div className="flex items-center space-x-2">
                                <div className="w-3 h-3 bg-green-500 rounded"></div>
                                <span>Detection Rate %</span>
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </>
                  ) : (
                    <div className="text-center py-12 text-muted-foreground">
                      <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>Submit IOCs to see file analysis results</p>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>Analysis Overview</CardTitle>
              <CardDescription>Results will appear here after analysis</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-muted-foreground">
                <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Submit IOCs to see analysis results</p>
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* IOC Results & File Analysis Results */}
      {detailedAnalysis && (
        <div className="space-y-6">
          {/* IOC Results Section */}
          <Card className="bg-gradient-to-r from-purple-600 to-blue-600 text-white border-none">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-xl font-semibold flex items-center space-x-2">
                  <Search className="h-5 w-5" />
                  <span>IOC Results</span>
                </CardTitle>
                <Button 
                  variant="ghost" 
                  size="sm" 
                  className="text-white hover:bg-white/20"
                  onClick={() => setIocResultsExpanded(!iocResultsExpanded)}
                >
                  <ChevronDown 
                    className={`h-4 w-4 transition-transform ${iocResultsExpanded ? 'rotate-180' : ''}`} 
                  />
                </Button>
              </div>
            </CardHeader>
            {iocResultsExpanded && (
              <CardContent>
                <div className="bg-red-500/20 border border-red-400/30 rounded-lg p-4 mb-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <AlertTriangle className="h-6 w-6 text-red-300" />
                      <div>
                        <h3 className="font-semibold text-red-100">CRITICAL THREAT DETECTED</h3>
                        <p className="text-sm text-red-200">High-risk malware identified with {detailedAnalysis.vtResults?.malicious || 31} engine detections</p>
                      </div>
                    </div>
                    <Button variant="destructive" size="sm">
                      IMMEDIATE ACTION REQUIRED
                    </Button>
                  </div>
                </div>
                
                {/* File Name and Risk Info */}
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <FileText className="h-5 w-5" />
                    <span className="font-semibold">{detailedAnalysis.fileInfo?.name || 'parafin.bin'}</span>
                    <Badge variant="secondary" className="text-red-600 bg-red-100">
                      HIGH RISK
                    </Badge>
                  </div>
                  <div className="text-sm text-blue-100">
                    <AlertTriangle className="h-4 w-4 inline mr-1" />
                    {detailedAnalysis.vtResults?.malicious || 31}/84 security vendors flagged this file as malicious
                  </div>
                </div>

                {/* Tab Navigation */}
                <div className="flex space-x-1 mb-4 bg-white/10 p-1 rounded-lg">
                  <button 
                    className={`px-4 py-2 text-sm font-medium rounded-md ${
                      activeTab === 'detection' 
                        ? 'bg-white/20 text-white' 
                        : 'text-white/70 hover:text-white hover:bg-white/10'
                    }`}
                    onClick={() => setActiveTab('detection')}
                  >
                    Detection
                  </button>
                  <button 
                    className={`px-4 py-2 text-sm font-medium rounded-md ${
                      activeTab === 'details' 
                        ? 'bg-white/20 text-white' 
                        : 'text-white/70 hover:text-white hover:bg-white/10'
                    }`}
                    onClick={() => setActiveTab('details')}
                  >
                    Details  
                  </button>
                  <button 
                    className={`px-4 py-2 text-sm font-medium rounded-md ${
                      activeTab === 'relations' 
                        ? 'bg-white/20 text-white' 
                        : 'text-white/70 hover:text-white hover:bg-white/10'
                    }`}
                    onClick={() => setActiveTab('relations')}
                  >
                    Relations
                  </button>
                  <button 
                    className={`px-4 py-2 text-sm font-medium rounded-md ${
                      activeTab === 'behavior' 
                        ? 'bg-white/20 text-white' 
                        : 'text-white/70 hover:text-white hover:bg-white/10'
                    }`}
                    onClick={() => setActiveTab('behavior')}
                  >
                    Behavior
                  </button>
                </div>

                {/* Tab Content */}
                <div>
                  {activeTab === 'detection' && (
                    <div className="grid gap-4 lg:grid-cols-3">
                      {/* Community Score */}
                      <div className="bg-white/10 rounded-lg p-6 text-center">
                        <div className="text-3xl font-bold text-red-300 mb-2">
                          {detailedAnalysis.riskScore}/84
                        </div>
                        <div className="text-sm text-white/80">Community Score</div>
                      </div>

                      {/* File Size */}
                      <div className="bg-white/10 rounded-lg p-6 text-center">
                        <div className="text-3xl font-bold text-blue-300 mb-2">
                          1.38 MB
                        </div>
                        <div className="text-sm text-white/80">Size</div>
                      </div>

                      {/* Last Analysis */}
                      <div className="bg-white/10 rounded-lg p-6 text-center">
                        <div className="text-3xl font-bold text-purple-300 mb-2">
                          30 hours ago
                        </div>
                        <div className="text-sm text-white/80">Last Analysis Date</div>
                      </div>
                    </div>
                  )}

                  {activeTab === 'details' && (
                    <div>
                      {/* Basic Properties Section */}
                      <div className="mb-6">
                        <h3 className="text-lg font-semibold mb-4 text-white">Basic properties</h3>
                        <div className="grid gap-4 lg:grid-cols-2">
                          {/* Left Column */}
                          <div className="space-y-4">
                            <div className="bg-white/10 p-4 rounded-lg">
                              <div className="text-sm font-medium text-white/60 mb-1">MD5</div>
                              <div className="text-sm font-mono break-all text-white">
                                {detailedAnalysis.fileInfo?.md5 || 'cf6eb0ac5cd413d93bef403f'}
                              </div>
                            </div>
                            
                            <div className="bg-white/10 p-4 rounded-lg">
                              <div className="text-sm font-medium text-white/60 mb-1">SHA256</div>
                              <div className="text-sm font-mono break-all text-white">
                                {detailedAnalysis.fileInfo?.sha256 || '8d24d4e72b7b22017c6d6e7b1a2dc1a1ead63b97b58114c02c221aa86dd9d00c'}
                              </div>
                            </div>

                            <div className="bg-white/10 p-4 rounded-lg">
                              <div className="text-sm font-medium text-white/60 mb-1">FILE TYPE</div>
                              <div className="text-sm text-white">{detailedAnalysis.fileInfo?.type || 'PE32 executable'}</div>
                            </div>

                            <div className="bg-white/10 p-4 rounded-lg">
                              <div className="text-sm font-medium text-white/60 mb-1">SIZE</div>
                              <div className="text-sm text-white">
                                1.38 MB (1445179 bytes)
                              </div>
                            </div>
                          </div>

                          {/* Right Column */}
                          <div className="space-y-4">
                            <div className="bg-white/10 p-4 rounded-lg">
                              <div className="text-sm font-medium text-white/60 mb-1">SHA1</div>
                              <div className="text-sm font-mono break-all text-white">
                                {detailedAnalysis.fileInfo?.sha1 || 'caa648e83b0068ec6fe05af2aca59631f'}
                              </div>
                            </div>
                            
                            <div className="bg-white/10 p-4 rounded-lg">
                              <div className="text-sm font-medium text-white/60 mb-1">TLSH</div>
                              <div className="text-sm font-mono break-all text-white">
                                {detailedAnalysis.fileInfo?.tlsh || 'T150C232C0D3C0AF2F8938383074594T15952329G522A0CD619G0AC0A1684'}
                              </div>
                            </div>

                            <div className="bg-white/10 p-4 rounded-lg">
                              <div className="text-sm font-medium text-white/60 mb-1">MAGIC</div>
                              <div className="text-sm text-white">{detailedAnalysis.fileInfo?.magic || 'PE32 executable (GUI) Intel 80386, for MS Windows'}</div>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* History Section */}
                      <div className="mb-6">
                        <h3 className="text-lg font-semibold mb-4 text-white">History</h3>
                        <div className="space-y-3">
                          <div className="flex justify-between items-center">
                            <span className="text-sm font-medium text-white">First Seen In The Wild</span>
                            <span className="text-sm text-white/80">{detailedAnalysis.fileInfo?.firstSeen || '2025-01-29 15:18:00 UTC'}</span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-sm font-medium text-white">Last Analysis</span>
                            <span className="text-sm text-white/80">{detailedAnalysis.fileInfo?.lastAnalysis || '30 hours ago'}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {activeTab === 'relations' && (
                    <div className="text-white/80">
                      <p>Relationship data and connections would be displayed here.</p>
                    </div>
                  )}

                  {activeTab === 'behavior' && (
                    <div className="text-white/80">
                      <p>Behavioral analysis data would be displayed here.</p>
                    </div>
                  )}
                </div>
              </CardContent>
            )}
          </Card>

          {/* File Analysis Results */}
          <Card className="bg-gradient-to-r from-blue-600 to-purple-600 text-white border-none">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-xl font-semibold flex items-center space-x-2">
                  <FileText className="h-5 w-5" />
                  <span>File Analysis Results</span>
                </CardTitle>
                <Button 
                  variant="ghost" 
                  size="sm" 
                  className="text-white hover:bg-white/20"
                >
                  <ChevronDown className="h-4 w-4" />
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {/* Comprehensive File Analysis Header */}
              <div className="bg-white/10 rounded-lg p-6 mb-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <Activity className="h-6 w-6 text-blue-300" />
                    <h3 className="text-lg font-semibold text-white">Comprehensive File Analysis</h3>
                    <Badge variant="secondary" className="bg-green-500/20 text-green-300 border-green-400/30">
                      Live Analysis
                    </Badge>
                  </div>
                </div>
                
                {/* Analysis Stats */}
                <div className="grid grid-cols-5 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-bold text-blue-300">1,445,179</div>
                    <div className="text-sm text-white/80">File Size (bytes)</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-red-300">{detailedAnalysis.vtResults?.malicious || 31}</div>
                    <div className="text-sm text-white/80">Threats Detected</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-green-300">{detailedAnalysis.vtResults?.harmless || 53}</div>
                    <div className="text-sm text-white/80">Clean Results</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-yellow-300">2.3s</div>
                    <div className="text-sm text-white/80">Analysis Time</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-purple-300">{detailedAnalysis.confidence}%</div>
                    <div className="text-sm text-white/80">Confidence</div>
                  </div>
                </div>
              </div>

              {/* Main Analysis Grid */}
              <div className="grid gap-6 lg:grid-cols-3 mb-6">
                {/* File Information */}
                <Card className="bg-white/10 border-white/20">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-white flex items-center space-x-2">
                      <FileText className="h-4 w-4" />
                      <span>File Information</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">File Name</div>
                      <div className="text-sm text-white font-mono">{detailedAnalysis.fileInfo?.name || 'parafin.bin'}</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">Size</div>
                      <div className="text-sm text-white">1.38 MB (1,445,179 bytes)</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">Type</div>
                      <div className="text-sm text-white">PE32 executable (GUI) Intel 80386, for MS Windows</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">MD5</div>
                      <div className="text-xs text-white font-mono break-all">cf6eb0ac5cd413d93bef403f</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">SHA256</div>
                      <div className="text-xs text-white font-mono break-all">8d24d4e72b7b22017c6d6e7b1a2dc1a1ead63b97b58114c02c221aa86dd9d00c</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">First Seen</div>
                      <div className="text-sm text-white">2025-01-29 15:18:00 UTC</div>
                    </div>
                  </CardContent>
                </Card>

                {/* Threat Classification */}
                <Card className="bg-white/10 border-white/20">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-white flex items-center space-x-2">
                      <AlertTriangle className="h-4 w-4" />
                      <span>Threat Classification</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">Primary Type</div>
                      <div className="text-sm">
                        <Badge variant="destructive" className="bg-red-500/20 text-red-300 border-red-400/30">
                          Trojan
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">Family</div>
                      <div className="text-sm">
                        <Badge variant="secondary" className="bg-orange-500/20 text-orange-300 border-orange-400/30">
                          Generic.KD
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">Severity</div>
                      <div className="text-sm">
                        <Badge variant="destructive" className="bg-red-500/20 text-red-300 border-red-400/30">
                          High
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">MITRE ATT&CK Tactics</div>
                      <div className="flex flex-wrap gap-1 mt-1">
                        <Badge variant="outline" className="text-xs bg-blue-500/20 text-blue-300 border-blue-400/30">Initial Access</Badge>
                        <Badge variant="outline" className="text-xs bg-blue-500/20 text-blue-300 border-blue-400/30">Defense Evasion</Badge>
                        <Badge variant="outline" className="text-xs bg-blue-500/20 text-blue-300 border-blue-400/30">Persistence</Badge>
                      </div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">Tags</div>
                      <div className="flex flex-wrap gap-1 mt-1">
                        <Badge variant="outline" className="text-xs bg-purple-500/20 text-purple-300 border-purple-400/30">trojan</Badge>
                        <Badge variant="outline" className="text-xs bg-purple-500/20 text-purple-300 border-purple-400/30">hijackloader</Badge>
                        <Badge variant="outline" className="text-xs bg-purple-500/20 text-purple-300 border-purple-400/30">malware</Badge>
                        <Badge variant="outline" className="text-xs bg-purple-500/20 text-purple-300 border-purple-400/30">pe32</Badge>
                        <Badge variant="outline" className="text-xs bg-purple-500/20 text-purple-300 border-purple-400/30">windows</Badge>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Sandbox Analysis */}
                <Card className="bg-white/10 border-white/20">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-white flex items-center space-x-2">
                      <Activity className="h-4 w-4" />
                      <span>Sandbox Analysis</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">Status</div>
                      <div className="text-sm">
                        <Badge variant="secondary" className="bg-green-500/20 text-green-300 border-green-400/30">
                          Analyzed
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">Runtime</div>
                      <div className="text-sm text-white">180s</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">Environment</div>
                      <div className="text-sm text-white">Windows 10 x64</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-white/60 uppercase tracking-wide">Behavioral Analysis</div>
                      <div className="space-y-2 mt-2">
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-white/80">File Creation</span>
                          <div className="flex items-center space-x-1">
                            <span className="text-xs text-white">7</span>
                            <Badge variant="secondary" className="text-xs bg-yellow-500/20 text-yellow-300 border-yellow-400/30">medium</Badge>
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-white/80">Registry Modification</span>
                          <div className="flex items-center space-x-1">
                            <span className="text-xs text-white">12</span>
                            <Badge variant="destructive" className="text-xs bg-red-500/20 text-red-300 border-red-400/30">high</Badge>
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-white/80">Network Communication</span>
                          <div className="flex items-center space-x-1">
                            <span className="text-xs text-white">3</span>
                            <Badge variant="destructive" className="text-xs bg-red-500/20 text-red-300 border-red-400/30">high</Badge>
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-white/80">Process Injection</span>
                          <div className="flex items-center space-x-1">
                            <span className="text-xs text-white">2</span>
                            <Badge variant="destructive" className="text-xs bg-red-500/20 text-red-300 border-red-400/30">critical</Badge>
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-white/80">Service Installation</span>
                          <div className="flex items-center space-x-1">
                            <span className="text-xs text-white">1</span>
                            <Badge variant="destructive" className="text-xs bg-red-500/20 text-red-300 border-red-400/30">high</Badge>
                          </div>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Detailed Antivirus Engine Results */}
              <Card className="bg-white/10 border-white/20 mb-6">
                <CardHeader>
                  <CardTitle className="text-white flex items-center space-x-2">
                    <Shield className="h-5 w-5" />
                    <span>Detailed Antivirus Engine Results</span>
                    <svg className="h-4 w-4 text-green-300" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-white/20">
                          <th className="text-left py-3 px-2 text-sm font-medium text-white/80">Vendor</th>
                          <th className="text-left py-3 px-2 text-sm font-medium text-white/80">Status</th>
                          <th className="text-left py-3 px-2 text-sm font-medium text-white/80">Verdict</th>
                          <th className="text-right py-3 px-2 text-sm font-medium text-white/80">Last Update</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/10">
                        {detailedAnalysis.vtResults?.engines.map((engine, index) => (
                          <tr key={index} className="hover:bg-white/5">
                            <td className="py-3 px-2">
                              <div className="flex items-center space-x-2">
                                <div className={`w-2 h-2 rounded-full ${
                                  engine.status === 'detected' ? 'bg-red-400' : 'bg-green-400'
                                }`} />
                                <span className="text-sm font-medium text-white">{engine.name}</span>
                              </div>
                            </td>
                            <td className="py-3 px-2">
                              <Badge 
                                variant={engine.status === 'detected' ? 'destructive' : 'secondary'}
                                className={
                                  engine.status === 'detected' 
                                    ? 'bg-red-500/20 text-red-300 border-red-400/30' 
                                    : 'bg-green-500/20 text-green-300 border-green-400/30'
                                }
                              >
                                {engine.status}
                              </Badge>
                            </td>
                            <td className="py-3 px-2">
                              <span className={`text-sm font-medium ${
                                engine.status === 'detected' ? 'text-red-300' : 'text-green-300'
                              }`}>
                                {engine.verdict}
                              </span>
                            </td>
                            <td className="py-3 px-2 text-right">
                              <span className="text-sm text-white/70">{engine.lastUpdate}</span>
                            </td>
                          </tr>
                        )) || []}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>

              {/* Engine Performance Analysis */}
              <Card className="bg-white/10 border-white/20">
                <CardHeader>
                  <CardTitle className="text-white flex items-center space-x-2">
                    <TrendingUp className="h-5 w-5" />
                    <span>Engine Performance Analysis</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="grid grid-cols-5 gap-4">
                      {['Rising', 'Trellix', 'Skyhigh', 'BitDefender', 'ESET'].map((engine, index) => {
                        const accuracy = [95, 88, 94, 87, 96][index];
                        const detections = [85, 78, 91, 75, 93][index];
                        
                        return (
                          <div key={engine} className="text-center">
                            <div className="mb-2">
                              <div className="text-sm font-medium text-white">{engine}</div>
                            </div>
                            <div 
                              className="relative h-32 w-16 mx-auto group cursor-pointer"
                            >
                              {/* Blue bar (Accuracy) */}
                              <div 
                                className="absolute bottom-0 w-8 bg-blue-500 rounded-t transition-all duration-200 hover:bg-blue-400"
                                style={{ height: `${accuracy}%` }}
                              />
                              {/* Green bar (Detections) */}
                              <div 
                                className="absolute bottom-0 right-0 w-8 bg-green-500 rounded-t transition-all duration-200 hover:bg-green-400"
                                style={{ height: `${detections}%` }}
                              />
                              
                              {/* Hover Tooltip */}
                              <div className="absolute -top-14 left-1/2 transform -translate-x-1/2 bg-black/90 text-white text-xs px-3 py-2 rounded shadow-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 z-10 whitespace-nowrap">
                                <div>Accuracy: {accuracy}%</div>
                                <div>Detections: {detections}</div>
                                <div className="absolute top-full left-1/2 transform -translate-x-1/2 w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-black/90"></div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    <div className="flex justify-center space-x-6 text-xs">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-blue-500 rounded"></div>
                        <span className="text-white/70">Accuracy %</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-green-500 rounded"></div>
                        <span className="text-white/70">Detection Rate %</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
