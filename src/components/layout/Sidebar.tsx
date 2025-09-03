'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  Shield, 
  Search, 
  Network, 
  History, 
  FileText, 
  ChevronLeft,
  ChevronRight,
  Activity,
  TrendingUp,
  Clock,
  AlertTriangle
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';

const navigationItems = [
  { 
    href: '/', 
    label: 'Dashboard', 
    icon: Shield, 
    description: 'Overview & Analytics',
    category: 'Main'
  },
  { 
    href: '/analyze', 
    label: 'Threat Hunting', 
    icon: Search, 
    description: 'IOC Analysis',
    category: 'Main'
  },
  { 
    href: '/graph', 
    label: 'Graph Analysis', 
    icon: Network, 
    description: 'Relationship Graph',
    category: 'Main'
  },
  { 
    href: '/history', 
    label: 'Reports & Alerts', 
    icon: History, 
    description: 'Analysis History',
    category: 'Main'
  },
];

interface SidebarProps {
  className?: string;
}

export function Sidebar({ className = '' }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [isMobile, setIsMobile] = useState(false);
  const pathname = usePathname();

  // Check for mobile screen and auto-collapse on mobile
  useEffect(() => {
    const checkIsMobile = () => {
      const mobile = window.innerWidth < 768;
      setIsMobile(mobile);
      if (mobile && !collapsed) {
        setCollapsed(true);
      }
    };

    checkIsMobile();
    window.addEventListener('resize', checkIsMobile);
    return () => window.removeEventListener('resize', checkIsMobile);
  }, [collapsed]);

  // Update the main content margin when sidebar collapses/expands
  useEffect(() => {
    const mainContent = document.getElementById('main-content');
    if (mainContent) {
      mainContent.style.marginLeft = collapsed ? '4rem' : '16rem';
    }
  }, [collapsed]);

  return (
    <div className={`relative ${className}`}>
      <div 
        className={`
          fixed left-0 top-0 z-50 h-screen bg-gradient-to-b from-[#0D1021] to-[#1B1F3B] 
          border-r border-slate-800/50 transition-all duration-300 ease-in-out
          ${collapsed ? 'w-16' : 'w-64'}
        `}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800/50">
          <div className={`flex items-center space-x-3 ${collapsed ? 'justify-center' : ''}`}>
            <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-purple-500 to-pink-500 shadow-lg shadow-purple-500/25">
              <Shield className="h-6 w-6 text-white" />
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="text-lg font-bold text-white">IOC Analyzer</span>
                <span className="text-xs text-slate-400">Forensic Cyber Tech</span>
              </div>
            )}
          </div>
          
          {!collapsed && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setCollapsed(true)}
              className="h-8 w-8 p-0 text-slate-400 hover:text-white hover:bg-slate-800/50"
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
          )}
        </div>

        {/* Expand Button - Only shown when collapsed */}
        {collapsed && (
          <div className="absolute top-4 -right-3 z-10">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setCollapsed(false)}
              className="h-6 w-6 p-0 rounded-full bg-slate-800 border border-slate-700 text-slate-400 hover:text-white hover:bg-slate-700"
            >
              <ChevronRight className="h-3 w-3" />
            </Button>
          </div>
        )}

        {/* Navigation */}
        <div className="flex-1 px-3 py-6">
          <nav className="space-y-2">
            {navigationItems.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href;
              
              return (
                <div key={item.href} className="relative group">
                  <Link href={item.href}>
                    <div
                      className={`
                        flex items-center px-3 py-3 rounded-lg transition-all duration-200
                        ${collapsed ? 'justify-center' : 'space-x-3'}
                        ${isActive 
                          ? 'bg-gradient-to-r from-purple-500/20 to-pink-500/20 border border-purple-500/30 shadow-lg shadow-purple-500/10 text-white' 
                          : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
                        }
                        relative overflow-hidden
                      `}
                    >
                      {/* Active Glow Effect */}
                      {isActive && (
                        <div className="absolute inset-0 bg-gradient-to-r from-purple-500/10 to-pink-500/10 animate-pulse" />
                      )}
                      
                      <div className="relative z-10 flex items-center w-full">
                        <Icon 
                          className={`
                            h-5 w-5 transition-colors
                            ${isActive ? 'text-purple-400' : 'text-current'}
                          `} 
                        />
                        {!collapsed && (
                          <div className="flex-1 min-w-0">
                            <div className="font-medium text-sm">{item.label}</div>
                            <div className="text-xs text-slate-400 truncate">{item.description}</div>
                          </div>
                        )}
                        {isActive && !collapsed && (
                          <div className="w-2 h-2 rounded-full bg-gradient-to-r from-purple-400 to-pink-400 shadow-lg shadow-purple-400/50" />
                        )}
                      </div>
                    </div>
                  </Link>
                  
                  {/* Tooltip for collapsed state */}
                  {collapsed && (
                    <div className="
                      absolute left-full top-1/2 -translate-y-1/2 ml-2 px-2 py-1 
                      bg-slate-900 border border-slate-700 rounded text-xs text-white
                      opacity-0 group-hover:opacity-100 transition-opacity duration-200
                      whitespace-nowrap z-50 pointer-events-none
                    ">
                      {item.label}
                      <div className="absolute top-1/2 -left-1 -translate-y-1/2 w-2 h-2 bg-slate-900 border-l border-b border-slate-700 rotate-45" />
                    </div>
                  )}
                </div>
              );
            })}
          </nav>
        </div>

        {/* System Status Widget */}
        <div className="border-t border-slate-800/50">
          {!collapsed ? (
            <div className="p-4 space-y-4">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wide">
                System Status
              </div>
              
              <div className="space-y-3">
                {/* Active Threats */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="h-4 w-4 text-red-400" />
                    <span className="text-xs text-slate-300">Active Threats</span>
                  </div>
                  <Badge variant="destructive" className="text-xs px-2 py-0.5">
                    7
                  </Badge>
                </div>
                
                {/* Detection Rate */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <TrendingUp className="h-4 w-4 text-green-400" />
                      <span className="text-xs text-slate-300">Detection Rate</span>
                    </div>
                    <span className="text-xs text-green-400 font-medium">94.2%</span>
                  </div>
                  <Progress value={94.2} className="h-1.5" />
                </div>
                
                {/* System Uptime */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Clock className="h-4 w-4 text-blue-400" />
                    <span className="text-xs text-slate-300">Uptime</span>
                  </div>
                  <span className="text-xs text-blue-400 font-medium">99.8%</span>
                </div>
                
                {/* System Activity */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Activity className="h-4 w-4 text-purple-400" />
                    <span className="text-xs text-slate-300">Activity</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                    <span className="text-xs text-slate-400">Live</span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-2 flex flex-col items-center space-y-2">
              <div className="w-8 h-8 rounded-full bg-gradient-to-r from-red-500 to-orange-500 flex items-center justify-center">
                <span className="text-xs font-bold text-white">7</span>
              </div>
              <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
