import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { Toaster } from '@/components/ui/sonner'
import { Navbar } from '@/components/layout/Navbar'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'EagleEye IOC Analyzer | Forensic Cyber Tech',
  description: 'Advanced IOC analysis platform with VirusTotal integration',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className={inter.className}>
        <div className="min-h-screen bg-background">
          <Navbar />
          <main className="container mx-auto px-4 py-6">
            {children}
          </main>
        </div>
        <Toaster />
      </body>
    </html>
  )
}
