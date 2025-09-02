'use client';

import React from 'react';
import Link from 'next/link';
import { 
  BarChart3, 
  Search, 
  Network, 
  Bell, 
  Download, 
  Settings, 
  User,
  Shield
} from 'lucide-react';

interface SidebarProps {
  activeModule?: string;
}

export function Sidebar({ activeModule = 'dashboard' }: SidebarProps) {
  const modules = [
    {
      id: 'dashboard',
      name: 'Dashboard',
      subtitle: 'Overview &...',
      icon: BarChart3,
      href: '/',
      active: activeModule === 'dashboard'
    },
    {
      id: 'threat-hunting',
      name: 'Threat Hunting',
      subtitle: 'IOC Analysis',
      icon: Search,
      href: '/analyze',
      active: activeModule === 'threat-hunting'
    },
    {
      id: 'graph-analysis',
      name: 'Graph Analysis',
      subtitle: 'Relationship Map',
      icon: Network,
      href: '/graph',
      active: activeModule === 'graph-analysis'
    }
  ];

  return (
    <div className="w-64 h-screen bg-[rgb(35,39,64)] border-r border-[rgb(55,65,81)] flex flex-col">
      {/* Header */}
      <div className="p-6 border-b border-[rgb(55,65,81)]">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-[rgb(147,51,234)] rounded-lg flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <span className="text-white font-semibold">IOC Analyzer</span>
        </div>
      </div>

      {/* Modules */}
      <div className="p-4">
        <div className="text-[rgb(156,163,175)] text-sm font-medium mb-4 flex items-center gap-2">
          <div className="w-5 h-5 rounded bg-[rgb(147,51,234)] flex items-center justify-center">
            <span className="text-white text-xs">◯</span>
          </div>
          Modules
        </div>
        
        <div className="space-y-2">
          {modules.map((module) => {
            const Icon = module.icon;
            return (
              <Link key={module.id} href={module.href}>
                <div className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-colors ${
                  module.active 
                    ? 'bg-[rgb(59,130,246)] text-white' 
                    : 'text-[rgb(156,163,175)] hover:bg-[rgb(55,65,81)] hover:text-white'
                }`}>
                  <Icon className="w-5 h-5" />
                  <div>
                    <div className="text-sm font-medium">{module.name}</div>
                    <div className="text-xs opacity-70">{module.subtitle}</div>
                  </div>
                </div>
              </Link>
            );
          })}
        </div>
      </div>

      {/* System Status */}
      <div className="mt-auto p-4 border-t border-[rgb(55,65,81)]">
        <div className="text-[rgb(156,163,175)] text-sm font-medium mb-3">System Status</div>
        <div className="space-y-2 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-[rgb(156,163,175)]">Active Threats</span>
            <div className="flex items-center gap-2">
              <span className="text-[rgb(239,68,68)] font-semibold">31</span>
              <div className="w-2 h-2 bg-[rgb(239,68,68)] rounded-full animate-pulse"></div>
            </div>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[rgb(156,163,175)]">Detection Rate</span>
            <span className="text-[rgb(34,197,94)] font-semibold">98.7%</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[rgb(156,163,175)]">Uptime</span>
            <span className="text-[rgb(34,197,94)] font-semibold">99.9%</span>
          </div>
        </div>
        
        <div className="mt-4 p-2 bg-[rgb(28,30,48)] rounded-lg">
          <div className="text-xs text-[rgb(156,163,175)]">System Health</div>
          <div className="flex items-center gap-2 mt-1">
            <div className="w-2 h-2 bg-[rgb(34,197,94)] rounded-full animate-pulse"></div>
            <span className="text-sm text-white">Online</span>
          </div>
        </div>
      </div>
    </div>
  );
}
