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
import { Search, Upload, CheckCircle, AlertCircle, Clock, Copy } from 'lucide-react';
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
    
    return <Badge variant={variants[verdict as keyof typeof variants] || 'outline'}>{verdict}</Badge>;
  };

  const getVerdictIcon = (verdict: string) => {
    switch (verdict) {
      case 'malicious':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      case 'suspicious':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'harmless':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Analyze IOCs</h1>
        <p className="text-muted-foreground">
          Submit indicators of compromise for VirusTotal analysis
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Analysis Form */}
        <Card>
          <CardHeader>
            <CardTitle>IOC Submission</CardTitle>
            <CardDescription>
              Enter IOCs one per line (IP, domain, URL, or file hash)
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
                      <FormLabel>IOCs</FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder="192.168.1.100&#10;malware.example.com&#10;http://suspicious-site.com&#10;d41d8cd98f00b204e9800998ecf8427e"
                          className="min-h-[150px] font-mono text-sm"
                          {...field}
                        />
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
                      <FormLabel>Label/Case ID (Optional)</FormLabel>
                      <FormControl>
                        <Input placeholder="Investigation 2024-001" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <div className="flex space-x-2">
                  <Button type="submit" disabled={isSubmitting} className="flex-1">
                    {isSubmitting ? (
                      <>
                        <Clock className="h-4 w-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Search className="h-4 w-4 mr-2" />
                        Analyze IOCs
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

        {/* Results */}
        <Card>
          <CardHeader>
            <CardTitle>Analysis Results</CardTitle>
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
                  <div className="p-3 rounded-lg bg-green-500/10">
                    <div className="text-2xl font-bold text-green-500">{results.created}</div>
                    <div className="text-sm text-muted-foreground">New</div>
                  </div>
                  <div className="p-3 rounded-lg bg-blue-500/10">
                    <div className="text-2xl font-bold text-blue-500">{results.fromCache}</div>
                    <div className="text-sm text-muted-foreground">Cached</div>
                  </div>
                  <div className="p-3 rounded-lg bg-red-500/10">
                    <div className="text-2xl font-bold text-red-500">{results.errors.length}</div>
                    <div className="text-sm text-muted-foreground">Errors</div>
                  </div>
                </div>

                {/* Results List */}
                <div className="space-y-2">
                  {results.items.map((item) => (
                    <div key={item._id} className="flex items-center justify-between p-3 rounded-lg border">
                      <div className="flex items-center space-x-3">
                        {getVerdictIcon(item.verdict)}
                        <div>
                          <p className="font-medium font-mono text-sm">{item.ioc}</p>
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

                {/* Errors */}
                {results.errors.length > 0 && (
                  <div className="space-y-2">
                    <h4 className="font-medium text-red-500">Errors:</h4>
                    {results.errors.map((error, index) => (
                      <p key={index} className="text-sm text-red-400 font-mono">
                        {error}
                      </p>
                    ))}
                  </div>
                )}
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
    </div>
  );
}
