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
import { 
  Search, Upload, CheckCircle, AlertCircle, Clock, Copy, Shield, TrendingUp, 
  FileText, Activity, AlertTriangle, Hash, Globe, Link, Zap, Eye, Target,
  BarChart3, PieChart, Cpu, Network, Database, Scan
} from 'lucide-react';
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
  const [activeSearchType, setActiveSearchType] = useState<'auto' | 'hash' | 'domain' | 'ip'>('auto');

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
      const iocList = data.iocs
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);

      const progressInterval = setInterval(() => {
        setProgress(prev => Math.min(prev + 10, 90));
      }, 200);

      const response = await fetch('/api/ioc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          iocs: iocList,
          label: data.label || 'Threat Hunt Analysis'
        }),
      });

      clearInterval(progressInterval);
      setProgress(100);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      setResults(result);

      if (result.items && result.items.length > 0) {
        // Mock detailed analysis for demonstration
        setDetailedAnalysis({
          fileInfo: {
            name: `${result.items[0].ioc}.sample`,
            size: 2048576,
            type: result.items[0].type,
            md5: result.items[0].ioc,
            sha1: `sha1_${result.items[0].ioc}`,
            sha256: `sha256_${result.items[0].ioc}`,
            uploadDate: new Date().toISOString(),
          },
          threatClassification: {
            primaryType: result.items[0].verdict === 'malicious' ? 'Trojan' : 'Clean',
            family: result.items[0].verdict === 'malicious' ? 'Generic.Malware' : 'N/A',
            severity: result.items[0].verdict === 'malicious' ? 'High' : 'Low',
            tags: result.items[0].verdict === 'malicious' ? ['trojan', 'backdoor'] : ['clean'],
          },
          vtResults: {
            malicious: result.items[0].verdict === 'malicious' ? 45 : 0,
            suspicious: result.items[0].verdict === 'malicious' ? 12 : 2,
            harmless: result.items[0].verdict === 'malicious' ? 8 : 65,
            undetected: result.items[0].verdict === 'malicious' ? 5 : 3,
            engines: [
              { name: 'Kaspersky', verdict: result.items[0].verdict, status: result.items[0].verdict === 'malicious' ? 'detected' : 'clean', lastUpdate: '2024-01-15' },
              { name: 'Microsoft', verdict: result.items[0].verdict, status: result.items[0].verdict === 'malicious' ? 'detected' : 'clean', lastUpdate: '2024-01-15' },
            ]
          },
          riskScore: result.items[0].verdict === 'malicious' ? 85 : 15,
          confidence: result.items[0].verdict === 'malicious' ? 92 : 98,
        });
      }

      toast.success(`Analysis completed! ${result.created} new IOCs analyzed.`);
    } catch (error) {
      console.error('Analysis failed:', error);
      toast.error('Analysis failed. Please try again.');
    } finally {
      setIsSubmitting(false);
      setTimeout(() => setProgress(0), 2000);
    }
  };

  const searchTypes = [
    { id: 'auto', label: 'Auto', icon: Zap, color: 'bg-blue-500' },
    { id: 'hash', label: 'Hash', icon: Hash, color: 'bg-purple-500' },
    { id: 'domain', label: 'Domain', icon: Globe, color: 'bg-green-500' },
    { id: 'ip', label: 'IP', icon: Network, color: 'bg-orange-500' },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <div className="container mx-auto p-6 space-y-6">
        {/* Header Section */}
        <div className="text-center space-y-4">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full mb-4">
            <Target className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
            Threat Hunting
          </h1>
          <p className="text-lg text-slate-300 max-w-2xl mx-auto">
            Advanced threat intelligence with real-time analysis powered by VirusTotal
          </p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="bg-gradient-to-r from-red-500/10 to-red-600/10 border-red-500/20 backdrop-blur-sm">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-red-300">Active Threats</p>
                  <p className="text-3xl font-bold text-red-400">31</p>
                </div>
                <AlertTriangle className="h-8 w-8 text-red-400" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-gradient-to-r from-green-500/10 to-green-600/10 border-green-500/20 backdrop-blur-sm">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-green-300">Detection Rate</p>
                  <p className="text-3xl font-bold text-green-400">98.7%</p>
                </div>
                <Shield className="h-8 w-8 text-green-400" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-blue-500/10 to-blue-600/10 border-blue-500/20 backdrop-blur-sm">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-blue-300">IOCs Analyzed</p>
                  <p className="text-3xl font-bold text-blue-400">12.4K</p>
                </div>
                <Database className="h-8 w-8 text-blue-400" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-purple-500/10 to-purple-600/10 border-purple-500/20 backdrop-blur-sm">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-purple-300">Scan Speed</p>
                  <p className="text-3xl font-bold text-purple-400">2.1s</p>
                </div>
                <Cpu className="h-8 w-8 text-purple-400" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Analysis Form */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <Search className="h-5 w-5 text-blue-400" />
                <span>IOC Intelligence Search</span>
                <Badge variant="secondary" className="ml-auto bg-blue-500/20 text-blue-300">Live</Badge>
              </CardTitle>
              <CardDescription className="text-slate-300">
                Enter IOCs (Hash, Domain, IP, URL) one per line for comprehensive threat analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Search Type Selector */}
              <div className="grid grid-cols-4 gap-2">
                {searchTypes.map((type) => (
                  <Button
                    key={type.id}
                    variant={activeSearchType === type.id ? "default" : "outline"}
                    className={`flex flex-col items-center p-4 h-auto space-y-2 ${
                      activeSearchType === type.id 
                        ? `${type.color} text-white border-none` 
                        : 'bg-slate-700/50 border-slate-600 text-slate-300 hover:bg-slate-600/50'
                    }`}
                    onClick={() => setActiveSearchType(type.id as any)}
                  >
                    <type.icon className="h-5 w-5" />
                    <span className="text-xs">{type.label}</span>
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
                        <FormLabel className="text-slate-300">IOCs to Analyze</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Textarea
                              {...field}
                              placeholder="Enter IOCs here... (one per line)&#10;&#10;Try searching:&#10;test&#10;bd9948b278b2a31725e6eb9a37b9fe8f7e654c74"
                              className="min-h-[120px] bg-slate-900/50 border-slate-600 text-white placeholder:text-slate-500 resize-none"
                              disabled={isSubmitting}
                            />
                            <Eye className="absolute top-3 right-3 h-4 w-4 text-slate-500" />
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="label"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-slate-300">Analysis Label (Optional)</FormLabel>
                        <FormControl>
                          <Input
                            {...field}
                            placeholder="e.g., Suspicious Email Investigation"
                            className="bg-slate-900/50 border-slate-600 text-white placeholder:text-slate-500"
                            disabled={isSubmitting}
                          />
                        </FormControl>
                      </FormItem>
                    )}
                  />

                  {progress > 0 && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-300">Analysis Progress</span>
                        <span className="text-blue-400">{progress}%</span>
                      </div>
                      <Progress 
                        value={progress} 
                        className="h-2 bg-slate-700"
                      />
                    </div>
                  )}

                  <Button
                    type="submit"
                    disabled={isSubmitting}
                    className="w-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white border-none"
                  >
                    {isSubmitting ? (
                      <>
                        <Scan className="mr-2 h-4 w-4 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Search className="mr-2 h-4 w-4" />
                        Start Analysis
                      </>
                    )}
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>

          {/* Real-time Threat Overview */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <BarChart3 className="h-5 w-5 text-green-400" />
                <span>Threat Detection Overview</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {/* Detection Pie Chart Visualization */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-slate-900/50 rounded-lg p-4 text-center">
                    <div className="relative w-24 h-24 mx-auto mb-2">
                      {/* Simple circular progress simulation */}
                      <div className="absolute inset-0 rounded-full bg-gradient-to-r from-green-400 to-blue-500 p-1">
                        <div className="bg-slate-900 rounded-full w-full h-full flex items-center justify-center">
                          <span className="text-green-400 font-bold">58%</span>
                        </div>
                      </div>
                    </div>
                    <p className="text-xs text-slate-400">Clean Files</p>
                  </div>
                  
                  <div className="bg-slate-900/50 rounded-lg p-4 text-center">
                    <div className="relative w-24 h-24 mx-auto mb-2">
                      <div className="absolute inset-0 rounded-full bg-gradient-to-r from-red-400 to-orange-500 p-1">
                        <div className="bg-slate-900 rounded-full w-full h-full flex items-center justify-center">
                          <span className="text-red-400 font-bold">42%</span>
                        </div>
                      </div>
                    </div>
                    <p className="text-xs text-slate-400">Threats</p>
                  </div>
                </div>

                {/* 24H Threat Trends Line Chart */}
                <div>
                  <h4 className="text-slate-300 text-sm font-medium mb-3 flex items-center">
                    <TrendingUp className="h-4 w-4 mr-2 text-blue-400" />
                    24H Threat Trends
                  </h4>
                  <div className="bg-slate-900/50 rounded-lg p-4">
                    {/* Simple line chart representation */}
                    <div className="h-32 flex items-end space-x-2">
                      {[12, 8, 15, 22, 18, 25, 30, 28, 16, 20, 14, 18].map((height, index) => (
                        <div key={index} className="flex-1 bg-gradient-to-t from-blue-500/50 to-blue-400/20 rounded-t-sm" style={{ height: `${height * 2}%` }} />
                      ))}
                    </div>
                    <div className="grid grid-cols-4 gap-2 mt-2 text-xs text-slate-500">
                      <span>00:00</span>
                      <span>06:00</span>
                      <span>12:00</span>
                      <span>18:00</span>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Results Section */}
        {results && (
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <FileText className="h-5 w-5 text-blue-400" />
                <span>Analysis Results</span>
                <Badge variant="secondary" className="bg-green-500/20 text-green-400">
                  {results.total} IOCs
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="bg-slate-900/50 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Total Analyzed</span>
                    <span className="text-2xl font-bold text-white">{results.total}</span>
                  </div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">New Entries</span>
                    <span className="text-2xl font-bold text-blue-400">{results.created}</span>
                  </div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">From Cache</span>
                    <span className="text-2xl font-bold text-green-400">{results.fromCache}</span>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                {results.items.map((item) => (
                  <div key={item._id} className="bg-slate-900/50 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className={`p-2 rounded-full ${
                          item.verdict === 'malicious' ? 'bg-red-500/20' :
                          item.verdict === 'suspicious' ? 'bg-yellow-500/20' : 'bg-green-500/20'
                        }`}>
                          {item.verdict === 'malicious' ? (
                            <AlertCircle className="h-4 w-4 text-red-400" />
                          ) : item.verdict === 'suspicious' ? (
                            <AlertTriangle className="h-4 w-4 text-yellow-400" />
                          ) : (
                            <CheckCircle className="h-4 w-4 text-green-400" />
                          )}
                        </div>
                        <div>
                          <p className="font-mono text-sm text-white">{item.ioc}</p>
                          <p className="text-xs text-slate-400">{item.type}</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge className={
                          item.verdict === 'malicious' ? 'bg-red-500/20 text-red-400' :
                          item.verdict === 'suspicious' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'
                        }>
                          {item.verdict}
                        </Badge>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => navigator.clipboard.writeText(item.ioc)}
                          className="text-slate-400 hover:text-white"
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Detailed Analysis */}
        {detailedAnalysis && (
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <Activity className="h-5 w-5 text-purple-400" />
                <span>Detailed Threat Analysis</span>
                <Badge className="bg-purple-500/20 text-purple-400">
                  Risk Score: {detailedAnalysis.riskScore}%
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div>
                    <h4 className="text-slate-300 font-medium mb-3">File Information</h4>
                    <div className="bg-slate-900/50 rounded-lg p-4 space-y-2">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Type</span>
                        <span className="text-white">{detailedAnalysis.fileInfo?.type}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Size</span>
                        <span className="text-white">{detailedAnalysis.fileInfo?.size.toLocaleString()} bytes</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">SHA256</span>
                        <span className="text-white font-mono text-xs">{detailedAnalysis.fileInfo?.sha256.slice(0, 16)}...</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-slate-300 font-medium mb-3">Threat Classification</h4>
                    <div className="bg-slate-900/50 rounded-lg p-4 space-y-2">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Type</span>
                        <span className="text-white">{detailedAnalysis.threatClassification?.primaryType}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Family</span>
                        <span className="text-white">{detailedAnalysis.threatClassification?.family}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Severity</span>
                        <Badge className={
                          detailedAnalysis.threatClassification?.severity === 'High' ? 'bg-red-500/20 text-red-400' :
                          detailedAnalysis.threatClassification?.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-green-500/20 text-green-400'
                        }>
                          {detailedAnalysis.threatClassification?.severity}
                        </Badge>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <h4 className="text-slate-300 font-medium mb-3">VirusTotal Results</h4>
                    <div className="bg-slate-900/50 rounded-lg p-4 space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div className="text-center">
                          <div className="text-2xl font-bold text-red-400">{detailedAnalysis.vtResults?.malicious}</div>
                          <div className="text-xs text-slate-400">Malicious</div>
                        </div>
                        <div className="text-center">
                          <div className="text-2xl font-bold text-yellow-400">{detailedAnalysis.vtResults?.suspicious}</div>
                          <div className="text-xs text-slate-400">Suspicious</div>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="text-center">
                          <div className="text-2xl font-bold text-green-400">{detailedAnalysis.vtResults?.harmless}</div>
                          <div className="text-xs text-slate-400">Harmless</div>
                        </div>
                        <div className="text-center">
                          <div className="text-2xl font-bold text-slate-400">{detailedAnalysis.vtResults?.undetected}</div>
                          <div className="text-xs text-slate-400">Undetected</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-slate-300 font-medium mb-3">Confidence Score</h4>
                    <div className="bg-slate-900/50 rounded-lg p-4">
                      <div className="flex justify-between items-center">
                        <span className="text-slate-400">Analysis Confidence</span>
                        <span className="text-2xl font-bold text-blue-400">{detailedAnalysis.confidence}%</span>
                      </div>
                      <Progress 
                        value={detailedAnalysis.confidence} 
                        className="mt-2 h-2 bg-slate-700"
                      />
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
