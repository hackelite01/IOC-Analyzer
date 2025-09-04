'use client';

import React, { useState, useRef, useEffect } from 'react';
import { useRouter, useSearchParams, usePathname } from 'next/navigation';
import { Search, Loader2 } from 'lucide-react';

interface NavbarSearchProps {
  /** If provided, call this instead of routing to /analyze */
  onAnalyze?: (query: string) => void;
  /** Initial value for the search input */
  initialValue?: string;
  /** CSS classes for styling */
  className?: string;
}

export const NavbarSearch: React.FC<NavbarSearchProps> = ({
  onAnalyze,
  initialValue = '',
  className = ''
}) => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  
  // Initialize query from URL params if on analyze page, otherwise use initialValue
  const getInitialQuery = () => {
    if (pathname === '/analyze') {
      return searchParams.get('q') || initialValue;
    }
    return initialValue;
  };

  const [query, setQuery] = useState(getInitialQuery());
  const [isSubmitting, setIsSubmitting] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Update query when URL params change (for back/forward navigation)
  useEffect(() => {
    if (pathname === '/analyze') {
      const urlQuery = searchParams.get('q');
      if (urlQuery !== null) {
        setQuery(urlQuery);
      }
    }
  }, [pathname, searchParams]);

  // Keyboard shortcut: Ctrl/Cmd+K to focus search
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
        event.preventDefault();
        inputRef.current?.focus();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Trim and normalize query
  const normalizeQuery = (input: string): string => {
    return input.trim().replace(/\s+/g, ' ');
  };

  // Handle form submission
  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    
    const normalizedQuery = normalizeQuery(query);
    
    // Ignore empty/whitespace-only input
    if (!normalizedQuery) {
      return;
    }

    setIsSubmitting(true);

    try {
      if (onAnalyze) {
        // Call provided analyze function
        await onAnalyze(normalizedQuery);
      } else {
        // Navigate to analyze page with query parameter
        const encodedQuery = encodeURIComponent(normalizedQuery);
        router.push(`/analyze?q=${encodedQuery}`);
      }
    } catch (error) {
      console.error('Search/analyze failed:', error);
    } finally {
      // Reset loading state after a short delay to allow navigation
      setTimeout(() => setIsSubmitting(false), 500);
    }
  };

  // Handle input changes
  const handleInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setQuery(event.target.value);
  };

  // Handle Enter key
  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Enter') {
      handleSubmit(event);
    }
  };

  return (
    <form 
      onSubmit={handleSubmit}
      className={`flex items-center space-x-2 ${className}`}
    >
      <div className="relative flex-1">
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
          disabled={isSubmitting}
          placeholder="Search IOCs, domains, hashes..."
          aria-label="Search for threat indicators"
          className={`
            w-full px-4 py-2 pl-10 pr-4
            bg-slate-700/50 border border-slate-600 rounded-lg
            text-white placeholder-slate-400
            focus:outline-none focus:ring-2 focus:ring-green-400 focus:border-transparent
            disabled:opacity-50 disabled:cursor-not-allowed
            transition-all duration-200
          `}
        />
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400" />
      </div>
      
      <button
        type="submit"
        disabled={isSubmitting || !normalizeQuery(query)}
        aria-label="Analyze threat indicators"
        className={`
          px-4 py-2 rounded-lg font-medium
          bg-green-600 hover:bg-green-700 text-white
          disabled:opacity-50 disabled:cursor-not-allowed
          focus:outline-none focus:ring-2 focus:ring-green-400 focus:ring-offset-2 focus:ring-offset-slate-800
          transition-all duration-200
          flex items-center space-x-2
        `}
      >
        {isSubmitting ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>Analyzing...</span>
          </>
        ) : (
          <>
            <Search className="h-4 w-4" />
            <span>Analyze</span>
          </>
        )}
      </button>
    </form>
  );
};

export default NavbarSearch;
