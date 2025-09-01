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
  const [activeTab, setActiveTab] = useState<'detection' | 'details' | 'relations' | 'behavior'>('detection');
  const [iocResultsExpanded, setIocResultsExpanded] = useState(true);
  const [fileAnalysisExpanded, setFileAnalysisExpanded] = useState(true);

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
      
      // Generate mock detailed analysis
      if (result.items && result.items.length > 0) {
        const firstItem = result.items[0];
        const mockAnalysis = generateMockDetailedAnalysis(firstItem);
        setDetailedAnalysis(mockAnalysis);
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
                    <div className="text-white/80">
                      <p>Detailed file information and metadata would be displayed here.</p>
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

          {/* File Analysis Results Section */}
          <Card className="border-gray-200">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-xl font-semibold flex items-center space-x-2">
                  <FileText className="h-5 w-5" />
                  <span>File Analysis Results</span>
                </CardTitle>
                <Button 
                  variant="ghost" 
                  size="sm"
                  onClick={() => setFileAnalysisExpanded(!fileAnalysisExpanded)}
                >
                  <ChevronDown 
                    className={`h-4 w-4 transition-transform ${fileAnalysisExpanded ? 'rotate-180' : ''}`} 
                  />
                </Button>
              </div>
            </CardHeader>
            {fileAnalysisExpanded && (
              <CardContent>
                {/* Basic Properties Section */}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold mb-4">Basic properties</h3>
                  <div className="grid gap-4 lg:grid-cols-2">
                    {/* Left Column */}
                    <div className="space-y-4">
                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-sm font-medium text-gray-500 mb-1">MD5</div>
                        <div className="text-sm font-mono break-all">
                          {detailedAnalysis.fileInfo?.md5 || 'cf6eb0ac5cd413d93bef403f'}
                        </div>
                      </div>
                      
                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-sm font-medium text-gray-500 mb-1">SHA256</div>
                        <div className="text-sm font-mono break-all">
                          {detailedAnalysis.fileInfo?.sha256 || '8d24d4e72b7b22017c6d6e7b1a2dc1a1ead63b97b58114c02c221aa86dd9d00c'}
                        </div>
                      </div>

                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-sm font-medium text-gray-500 mb-1">FILE TYPE</div>
                        <div className="text-sm">{detailedAnalysis.fileInfo?.type || 'PE32 executable'}</div>
                      </div>

                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-sm font-medium text-gray-500 mb-1">SIZE</div>
                        <div className="text-sm">
                          1.38 MB (1445179 bytes)
                        </div>
                      </div>
                    </div>

                    {/* Right Column */}
                    <div className="space-y-4">
                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-sm font-medium text-gray-500 mb-1">SHA1</div>
                        <div className="text-sm font-mono break-all">
                          {detailedAnalysis.fileInfo?.sha1 || 'caa648e83b0068ec6fe05af2aca59631f'}
                        </div>
                      </div>
                      
                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-sm font-medium text-gray-500 mb-1">TLSH</div>
                        <div className="text-sm font-mono break-all">
                          {detailedAnalysis.fileInfo?.tlsh || 'T150C232C0D3C0AF2F8938383074594T15952329G522A0CD619G0AC0A1684'}
                        </div>
                      </div>

                      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                        <div className="text-sm font-medium text-gray-500 mb-1">MAGIC</div>
                        <div className="text-sm">{detailedAnalysis.fileInfo?.magic || 'PE32 executable (GUI) Intel 80386, for MS Windows'}</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* History Section */}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold mb-4">History</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium">First Seen In The Wild</span>
                      <span className="text-sm text-gray-600">{detailedAnalysis.fileInfo?.firstSeen || '2025-01-29 15:18:00 UTC'}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium">Last Analysis</span>
                      <span className="text-sm text-gray-600">{detailedAnalysis.fileInfo?.lastAnalysis || '30 hours ago'}</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            )}
          </Card>

          {/* Security Vendors Analysis */}
          {detailedAnalysis.vtResults && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5" />
                  <span>Security vendors&apos; analysis</span>
                  <svg className="h-4 w-4 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {detailedAnalysis.vtResults.engines.map((engine, index) => (
                    <div key={index} className="flex items-center justify-between p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800">
                      <div className="flex items-center space-x-3">
                        <div className={`w-3 h-3 rounded-full ${
                          engine.status === 'detected' ? 'bg-red-500' : 'bg-green-500'
                        }`} />
                        <span className="font-medium">{engine.name}</span>
                      </div>
                      <div className="flex items-center space-x-6">
                        <span className={`text-sm font-medium ${
                          engine.status === 'detected' ? 'text-red-500' : 'text-green-500'
                        }`}>
                          {engine.verdict}
                        </span>
                        <div className="w-32 h-2 bg-gray-200 rounded-full">
                          <div className={`h-full rounded-full ${
                            engine.status === 'detected' ? 'bg-red-500 w-full' : 'bg-green-500 w-0'
                          }`} />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
