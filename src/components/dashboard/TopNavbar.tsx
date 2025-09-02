'use client';

import React from 'react';
import { Search, Download, Bell, Settings, User } from 'lucide-react';

export function TopNavbar() {
  return (
    <div className="h-16 bg-[rgb(28,30,48)] border-b border-[rgb(55,65,81)] flex items-center justify-between px-6">
      {/* Search */}
      <div className="flex-1 max-w-md">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[rgb(107,114,128)]" />
          <input
            type="text"
            placeholder="Search IOCs, domains, IPs, file hashes..."
            className="w-full pl-10 pr-4 py-2 bg-[rgb(35,39,64)] border border-[rgb(55,65,81)] rounded-lg text-white placeholder-[rgb(107,114,128)] focus:outline-none focus:ring-2 focus:ring-[rgb(59,130,246)] focus:border-transparent"
          />
          <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
            <span className="text-xs text-[rgb(107,114,128)] bg-[rgb(55,65,81)] px-1.5 py-0.5 rounded">⌘ K</span>
          </div>
        </div>
      </div>

      {/* Right Section */}
      <div className="flex items-center gap-4 ml-6">
        {/* Live Monitoring */}
        <div className="text-[rgb(156,163,175)] text-sm flex items-center gap-2">
          <div className="w-2 h-2 bg-[rgb(34,197,94)] rounded-full animate-pulse"></div>
          Live monitoring active
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button className="p-2 text-[rgb(156,163,175)] hover:text-white hover:bg-[rgb(55,65,81)] rounded-lg transition-colors">
            <Download className="w-4 h-4" />
          </button>
          <button className="p-2 text-[rgb(156,163,175)] hover:text-white hover:bg-[rgb(55,65,81)] rounded-lg transition-colors relative">
            <Bell className="w-4 h-4" />
            <div className="absolute -top-1 -right-1 w-3 h-3 bg-[rgb(239,68,68)] rounded-full text-white text-xs flex items-center justify-center">
              1
            </div>
          </button>
          <button className="p-2 text-[rgb(156,163,175)] hover:text-white hover:bg-[rgb(55,65,81)] rounded-lg transition-colors">
            <Settings className="w-4 h-4" />
          </button>
        </div>

        {/* User Profile */}
        <div className="flex items-center gap-3 pl-4 border-l border-[rgb(55,65,81)]">
          <div className="w-8 h-8 bg-[rgb(147,51,234)] rounded-lg flex items-center justify-center">
            <User className="w-4 h-4 text-white" />
          </div>
          <div className="text-sm">
            <div className="text-white font-medium">Admin User</div>
            <div className="text-[rgb(156,163,175)]">• Online</div>
          </div>
        </div>
      </div>
    </div>
  );
}
