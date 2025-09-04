import React from 'react'
import { useAuth } from '@/contexts/AuthContext'
import LoginPage from '@/components/auth/LoginPage'

interface ProtectedRouteProps {
  children: React.ReactNode
  requireAdmin?: boolean
}

export default function ProtectedRoute({ children, requireAdmin = false }: ProtectedRouteProps) {
  const { isAuthenticated, isAdmin, loading, user } = useAuth()

  // Show loading spinner while checking authentication
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading...</p>
        </div>
      </div>
    )
  }

  // Show login page if not authenticated
  if (!isAuthenticated) {
    return <LoginPage />
  }

  // Show access denied if admin required but user is not admin
  if (requireAdmin && !isAdmin) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        <div className="text-center">
          <div className="bg-red-900/20 border border-red-500 text-red-400 px-6 py-4 rounded-lg">
            <h2 className="text-xl font-semibold mb-2">Access Denied</h2>
            <p>You need administrator privileges to access this page.</p>
            <p className="text-sm mt-2">Current role: {user?.role}</p>
          </div>
        </div>
      </div>
    )
  }

  // Render the protected content
  return <>{children}</>
}
