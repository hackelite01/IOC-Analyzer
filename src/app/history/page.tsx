'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Search, Download, Eye, RefreshCw, Calendar } from 'lucide-react';
import { format } from 'date-fns';

interface IOCRecord {
  _id: string;
  ioc: string;
  type: string;
  label?: string;
  vt: {
    normalized: {
      verdict: string;
      stats: {
        malicious: number;
        suspicious: number;
        harmless: number;
        undetected: number;
      };
      reputation?: number;
      last_analysis_date?: string;
    };
  };
  fetchedAt: string;
  updatedAt: string;
}

// Mock data for demonstration
const mockRecords: IOCRecord[] = [
  {
    _id: '1',
    ioc: '8.8.8.8',
    type: 'ip',
    label: 'DNS Server Check',
    vt: {
      normalized: {
        verdict: 'harmless',
        stats: { malicious: 0, suspicious: 0, harmless: 85, undetected: 5 },
        reputation: 0,
        last_analysis_date: '2025-01-01T10:30:00Z'
      }
    },
    fetchedAt: '2025-01-01T10:30:00Z',
    updatedAt: '2025-01-01T10:30:00Z'
  },
  {
    _id: '2',
    ioc: 'malware-test.com',
    type: 'domain',
    label: 'Threat Analysis',
    vt: {
      normalized: {
        verdict: 'malicious',
        stats: { malicious: 12, suspicious: 3, harmless: 0, undetected: 75 },
        reputation: -50,
        last_analysis_date: '2025-01-01T09:15:00Z'
      }
    },
    fetchedAt: '2025-01-01T09:15:00Z',
    updatedAt: '2025-01-01T09:15:00Z'
  },
  {
    _id: '3',
    ioc: 'http://suspicious-site.example',
    type: 'url',
    vt: {
      normalized: {
        verdict: 'suspicious',
        stats: { malicious: 0, suspicious: 5, harmless: 10, undetected: 75 },
        reputation: -10,
        last_analysis_date: '2024-12-31T18:45:00Z'
      }
    },
    fetchedAt: '2024-12-31T18:45:00Z',
    updatedAt: '2024-12-31T18:45:00Z'
  },
  {
    _id: '4',
    ioc: 'd41d8cd98f00b204e9800998ecf8427e',
    type: 'hash',
    label: 'File Analysis',
    vt: {
      normalized: {
        verdict: 'undetected',
        stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 90 },
        last_analysis_date: '2024-12-31T16:20:00Z'
      }
    },
    fetchedAt: '2024-12-31T16:20:00Z',
    updatedAt: '2024-12-31T16:20:00Z'
  }
];

export default function HistoryPage() {
  const [records, setRecords] = useState<IOCRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [verdictFilter, setVerdictFilter] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  useEffect(() => {
    // Load mock data
    setRecords(mockRecords);
  }, []);

  const filteredRecords = records.filter(record => {
    const matchesSearch = searchQuery === '' || 
      record.ioc.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (record.label && record.label.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesType = typeFilter === 'all' || record.type === typeFilter;
    const matchesVerdict = verdictFilter === 'all' || record.vt.normalized.verdict === verdictFilter;
    
    return matchesSearch && matchesType && matchesVerdict;
  });

  const totalPages = Math.ceil(filteredRecords.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedRecords = filteredRecords.slice(startIndex, startIndex + itemsPerPage);

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

  const exportData = (format: 'csv' | 'json') => {
    // Implementation for export functionality
    console.log(`Exporting ${filteredRecords.length} records as ${format}`);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Analysis History</h1>
        <p className="text-muted-foreground">
          Browse and manage your IOC analysis history
        </p>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
          <CardDescription>
            Filter and search through your analysis history
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <Input
                placeholder="Search IOCs or labels..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full"
              />
            </div>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="w-full sm:w-[180px]">
                <SelectValue placeholder="All Types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="ip">IP Address</SelectItem>
                <SelectItem value="domain">Domain</SelectItem>
                <SelectItem value="url">URL</SelectItem>
                <SelectItem value="hash">Hash</SelectItem>
              </SelectContent>
            </Select>
            <Select value={verdictFilter} onValueChange={setVerdictFilter}>
              <SelectTrigger className="w-full sm:w-[180px]">
                <SelectValue placeholder="All Verdicts" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Verdicts</SelectItem>
                <SelectItem value="malicious">Malicious</SelectItem>
                <SelectItem value="suspicious">Suspicious</SelectItem>
                <SelectItem value="harmless">Harmless</SelectItem>
                <SelectItem value="undetected">Undetected</SelectItem>
              </SelectContent>
            </Select>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => exportData('csv')}>
                <Download className="h-4 w-4 mr-2" />
                CSV
              </Button>
              <Button variant="outline" onClick={() => exportData('json')}>
                <Download className="h-4 w-4 mr-2" />
                JSON
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      <Card>
        <CardHeader>
          <CardTitle>Results</CardTitle>
          <CardDescription>
            Showing {paginatedRecords.length} of {filteredRecords.length} records
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IOC</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Detections</TableHead>
                  <TableHead>Label</TableHead>
                  <TableHead>Analyzed</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginatedRecords.map((record) => (
                  <TableRow key={record._id}>
                    <TableCell className="font-mono text-sm max-w-xs truncate">
                      {record.ioc}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="uppercase">
                        {record.type}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {getVerdictBadge(record.vt.normalized.verdict)}
                    </TableCell>
                    <TableCell>
                      <div className="text-sm space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 bg-red-500 rounded-full"></span>
                          <span>{record.vt.normalized.stats.malicious} malicious</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 bg-yellow-500 rounded-full"></span>
                          <span>{record.vt.normalized.stats.suspicious} suspicious</span>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      {record.label && (
                        <Badge variant="secondary">{record.label}</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {format(new Date(record.fetchedAt), 'MMM d, yyyy HH:mm')}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Button size="sm" variant="ghost">
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button size="sm" variant="ghost">
                          <RefreshCw className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4">
              <div className="text-sm text-muted-foreground">
                Page {currentPage} of {totalPages}
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                  disabled={currentPage === totalPages}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
