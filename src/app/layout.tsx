'use client'

import { Inter } from 'next/font/google'
import './globals.css'
import { Toaster } from '@/components/ui/sonner'
import { Sidebar } from '@/components/layout/Sidebar'
import { TopBar } from '@/components/layout/TopBar'
import { AuthProvider } from '@/contexts/AuthContext'
import ProtectedRoute from '@/components/auth/ProtectedRoute'

const inter = Inter({ subsets: ['latin'] })

function AuthenticatedLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <div className="min-h-screen bg-[rgb(20,20,32)] flex">
      <Sidebar />
      <div className="flex-1 flex flex-col ml-64 transition-all duration-300" id="main-content">
        <TopBar />
        <main className="flex-1 p-6 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  )
}

function RootLayoutClient({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <AuthProvider>
      <ProtectedRoute>
        <AuthenticatedLayout>
          {children}
        </AuthenticatedLayout>
      </ProtectedRoute>
    </AuthProvider>
  )
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className={inter.className}>
        <RootLayoutClient>
          {children}
        </RootLayoutClient>
        <Toaster />
      </body>
    </html>
  )
}
