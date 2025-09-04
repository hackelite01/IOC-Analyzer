import React, { createContext, useContext, useEffect, useState } from 'react'

interface User {
  id: string
  username: string
  email: string
  role: 'admin' | 'user'
  createdAt: string
}

interface AuthContextType {
  user: User | null
  token: string | null
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>
  logout: () => void
  loading: boolean
  isAuthenticated: boolean
  isAdmin: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: React.ReactNode
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  // Initialize auth state from localStorage
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        const storedToken = localStorage.getItem('auth_token')
        if (storedToken) {
          setToken(storedToken)
          await fetchUserProfile(storedToken)
        }
      } catch (error) {
        console.error('Failed to initialize auth:', error)
        // Clear invalid token
        localStorage.removeItem('auth_token')
      } finally {
        setLoading(false)
      }
    }

    initializeAuth()
  }, [])

  const fetchUserProfile = async (authToken: string) => {
    try {
      const response = await fetch('/api/auth/me', {
        headers: {
          'Authorization': `Bearer ${authToken}`,
        },
      })

      if (response.ok) {
        const data = await response.json()
        setUser(data.user)
      } else {
        throw new Error('Failed to fetch user profile')
      }
    } catch (error) {
      console.error('Failed to fetch user profile:', error)
      // Clear invalid token
      localStorage.removeItem('auth_token')
      setToken(null)
      setUser(null)
    }
  }

  const login = async (email: string, password: string): Promise<{ success: boolean; error?: string }> => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      })

      const data = await response.json()

      if (response.ok) {
        setToken(data.token)
        setUser(data.user)
        localStorage.setItem('auth_token', data.token)
        return { success: true }
      } else {
        return { success: false, error: data.error || 'Login failed' }
      }
    } catch (error) {
      console.error('Login error:', error)
      return { success: false, error: 'Network error' }
    }
  }

  const logout = () => {
    setUser(null)
    setToken(null)
    localStorage.removeItem('auth_token')
  }

  const isAuthenticated = !!user && !!token
  const isAdmin = user?.role === 'admin'

  const value: AuthContextType = {
    user,
    token,
    login,
    logout,
    loading,
    isAuthenticated,
    isAdmin,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

// Custom hook for making authenticated API calls
export const useAuthenticatedFetch = () => {
  const { token } = useAuth()

  const authenticatedFetch = React.useCallback(async (url: string, options: RequestInit = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
      ...options.headers,
    }

    return fetch(url, {
      ...options,
      headers,
    })
  }, [token])

  return authenticatedFetch
}
