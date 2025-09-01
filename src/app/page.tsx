'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Shield, Activity, AlertTriangle, CheckCircle, Search, TrendingUp } from 'lucide-react';
import Link from 'next/link';

// Mock data for demonstration
const recentAnalyses = [
  { id: '1', ioc: '192.168.1.100', type: 'ip', verdict: 'harmless', timestamp: '2 minutes ago' },
  { id: '2', ioc: 'malware.example.com', type: 'domain', verdict: 'malicious', timestamp: '15 minutes ago' },
  { id: '3', ioc: 'http://suspicious-site.com', type: 'url', verdict: 'suspicious', timestamp: '1 hour ago' },
  { id: '4', ioc: 'd41d8cd98f00b204e9800998ecf8427e', type: 'hash', verdict: 'undetected', timestamp: '2 hours ago' },
];

const stats = [
  { title: 'Total Analyses', value: '2,847', change: '+12%', icon: Activity, color: 'text-blue-500' },
  { title: 'Malicious IOCs', value: '23', change: '+2', icon: AlertTriangle, color: 'text-red-500' },
  { title: 'Clean IOCs', value: '2,764', change: '+18%', icon: CheckCircle, color: 'text-green-500' },
  { title: 'Detection Rate', value: '98.2%', change: '+0.5%', icon: TrendingUp, color: 'text-purple-500' },
];

function getVerdictBadge(verdict: string) {
  const variants = {
    malicious: 'destructive',
    suspicious: 'secondary',
    harmless: 'default',
    undetected: 'outline',
  } as const;
  
  return <Badge variant={variants[verdict as keyof typeof variants] || 'outline'}>{verdict}</Badge>;
}

export default function Dashboard() {
  return (
    <div className="space-y-6">
      {/* Hero Section */}
      <div className="bg-gradient-to-r from-primary/10 to-secondary/10 rounded-lg p-8">
        <div className="max-w-2xl">
          <h1 className="text-4xl font-bold mb-4">
            IOC Analysis Platform
          </h1>
          <p className="text-xl text-muted-foreground mb-6">
            Analyze indicators of compromise with integrated VirusTotal intelligence
          </p>
          <Link href="/analyze">
            <Button size="lg" className="mr-4">
              <Search className="h-5 w-5 mr-2" />
              Analyze IOCs
            </Button>
          </Link>
          <Link href="/history">
            <Button variant="outline" size="lg">
              View History
            </Button>
          </Link>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.title}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  {stat.title}
                </CardTitle>
                <Icon className={`h-4 w-4 ${stat.color}`} />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stat.value}</div>
                <p className="text-xs text-muted-foreground">
                  <span className="text-green-500">{stat.change}</span> from last month
                </p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Quick Analysis */}
        <Card>
          <CardHeader>
            <CardTitle>Quick Analysis</CardTitle>
            <CardDescription>
              Submit IOCs for immediate analysis
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              placeholder="Enter IOCs (one per line)&#10;192.168.1.100&#10;malware.example.com&#10;http://suspicious-site.com"
              className="min-h-[100px]"
            />
            <div className="flex items-center space-x-2">
              <Input
                placeholder="Case/Label (optional)"
                className="flex-1"
              />
              <Button>
                <Search className="h-4 w-4 mr-2" />
                Analyze
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Recent Analyses */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Analyses</CardTitle>
            <CardDescription>
              Latest IOC analysis results
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentAnalyses.map((analysis) => (
                <div key={analysis.id} className="flex items-center justify-between p-3 rounded-lg border">
                  <div className="flex items-center space-x-3">
                    <Shield className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="font-medium truncate">{analysis.ioc}</p>
                      <p className="text-sm text-muted-foreground">
                        {analysis.type}  {analysis.timestamp}
                      </p>
                    </div>
                  </div>
                  {getVerdictBadge(analysis.verdict)}
                </div>
              ))}
            </div>
            <div className="mt-4">
              <Link href="/history">
                <Button variant="outline" className="w-full">
                  View All Analyses
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
