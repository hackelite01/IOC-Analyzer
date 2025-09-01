'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Shield, Search, History, FileText } from 'lucide-react';

const navItems = [
  { href: '/', label: 'Dashboard', icon: Shield },
  { href: '/analyze', label: 'Analyze', icon: Search },
  { href: '/history', label: 'History', icon: History },
];

export function Navbar() {
  const pathname = usePathname();

  return (
    <nav className="border-b bg-card">
      <div className="container mx-auto px-4">
        <div className="flex h-16 items-center justify-between">
          <div className="flex items-center space-x-8">
            <Link href="/" className="flex items-center space-x-2">
              <Shield className="h-6 w-6 text-primary" />
              <div className="flex flex-col">
                <span className="text-lg font-bold">EagleEye</span>
                <span className="text-xs text-muted-foreground">Forensic Cyber Tech</span>
              </div>
            </Link>
            
            <div className="hidden md:flex items-center space-x-4">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = pathname === item.href;
                return (
                  <Link key={item.href} href={item.href}>
                    <Button
                      variant={isActive ? 'default' : 'ghost'}
                      size="sm"
                      className="flex items-center space-x-2"
                    >
                      <Icon className="h-4 w-4" />
                      <span>{item.label}</span>
                    </Button>
                  </Link>
                );
              })}
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <Button variant="outline" size="sm">
              <FileText className="h-4 w-4 mr-2" />
              Docs
            </Button>
          </div>
        </div>
      </div>
    </nav>
  );
}
