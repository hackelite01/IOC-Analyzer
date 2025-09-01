# EagleEye IOC Analyzer

A production-grade IOC (Indicator of Compromise) analysis platform built with Next.js, TypeScript, and VirusTotal integration.

##  Features

- **Multi-IOC Analysis**: Submit IPs, domains, URLs, and file hashes for analysis
- **VirusTotal Integration**: Real-time threat intelligence from VirusTotal API
- **Interactive Dashboard**: Modern UI with charts, filters, and search capabilities
- **Analysis History**: Track and manage past IOC analyses with pagination and export
- **Rate Limiting**: Built-in rate limiting for VirusTotal API compliance
- **MongoDB Storage**: Persistent storage with intelligent caching
- **Dark Mode UI**: Professional dark-themed interface using shadcn/ui
- **Export Functionality**: Export analysis results as CSV or JSON
- **Docker Support**: Full containerization for easy deployment

##  Tech Stack

### Frontend
- **Next.js 15+** (App Router, TypeScript)
- **Tailwind CSS** + **shadcn/ui** for styling
- **React Hook Form** + **Zod** for form validation
- **TanStack Query** for state management
- **ECharts** for data visualization
- **Lucide React** for icons

### Backend
- **Next.js API Routes** (TypeScript)
- **MongoDB** with **Mongoose** ODM
- **VirusTotal API v3** integration
- **Axios** for HTTP requests
- **Pino** for structured logging

### DevOps & Testing
- **Docker** + **Docker Compose**
- **Jest** + **Testing Library** for unit tests
- **Playwright** for E2E testing
- **ESLint** + **Prettier** for code quality

##  Setup

### Prerequisites
- Node.js 20+ and npm 10+
- MongoDB instance (local or cloud)
- VirusTotal API key

### Environment Variables

Create `.env.local`:

```bash
# VirusTotal API Configuration
VT_API_KEY=your-virustotal-api-key-here

# MongoDB Configuration  
MONGODB_URI=mongodb+srv://user:pass@cluster/ioc-analyzer?retryWrites=true&w=majority

# Internal API Security
INTERNAL_API_KEY=change-me-in-production

# Application Environment
NODE_ENV=development

# Optional Settings
HARD_DELETE=false
AUDIT_TTL_DAYS=90
VT_RATE_LIMIT_PER_MIN=4
```

### Local Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Open browser
# Navigate to http://localhost:3000
```

### Docker Development

```bash
# Start all services (app + MongoDB + Mongo Express)
npm run docker:up

# Stop all services
npm run docker:down

# Build production image
npm run docker:build
```

##  Usage

### 1. Analyze IOCs

1. Navigate to `/analyze`
2. Enter IOCs (one per line):
   - IP addresses: `8.8.8.8`
   - Domains: `example.com`
   - URLs: `http://suspicious-site.com`
   - Hashes: `d41d8cd98f00b204e9800998ecf8427e`
3. Optional: Add a case label
4. Click "Analyze IOCs"

### 2. View Results

- Real-time analysis progress with status indicators
- Verdict badges (Malicious/Suspicious/Harmless/Undetected)
- Detection statistics from multiple AV engines
- Reputation scores and categorization

### 3. Browse History

1. Navigate to `/history`
2. Use filters to search by:
   - IOC content
   - IOC type (IP/Domain/URL/Hash)
   - Verdict status
   - Date range
3. Export filtered results as CSV or JSON

### 4. Dashboard Overview

- Quick IOC submission form
- Recent analysis summary
- Key performance indicators
- System health status

##  API Endpoints

### IOC Analysis
- `POST /api/ioc` - Submit IOCs for analysis
- `GET /api/ioc` - List analysis results (with filtering)
- `GET /api/ioc/[id]` - Get specific IOC details
- `PATCH /api/ioc/[id]` - Re-fetch IOC from VirusTotal
- `DELETE /api/ioc/[id]` - Remove IOC record

### System
- `GET /health` - Health check endpoint

##  Testing

```bash
# Run unit tests
npm run test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage

# Run E2E tests
npx playwright test
```

##  Deployment

### Docker Production

```bash
# Build production image
docker build -t ioc-analyzer .

# Run with environment variables
docker run -d \
  -p 3000:3000 \
  -e MONGODB_URI=your-mongo-uri \
  -e VT_API_KEY=your-vt-api-key \
  ioc-analyzer
```

### Vercel Deployment

1. Connect repository to Vercel
2. Set environment variables in Vercel dashboard
3. Use MongoDB Atlas for database
4. Deploy automatically on push

##  Project Structure

```
ioc-analyzer-pro/
 src/
    app/                    # Next.js App Router pages
       api/               # API route handlers
       analyze/           # IOC analysis page
       history/           # Analysis history
       health/            # Health check
    components/            # Reusable React components
       ui/               # shadcn/ui components
       layout/           # Layout components
    lib/                   # Utility libraries
        models/           # Mongoose models
        db.ts             # Database connection
        vt.ts             # VirusTotal client
        detect.ts         # IOC detection
        normalize.ts      # Data normalization
        validators.ts     # Zod schemas
 tests/                     # Test files
 docker-compose.yml         # Development containers
 Dockerfile                 # Production container
 README.md                  # This file
```

##  Configuration

### VirusTotal Rate Limiting

The application implements intelligent rate limiting:
- Respects VirusTotal API limits (default: 4 requests/minute)
- Automatic retry with exponential backoff
- 429 error handling with proper delays

### MongoDB Indexing

Optimized database indexes:
- Compound index on `ioc + type` (unique)
- Verdict filtering index
- Timestamp-based queries
- Label/case ID searches

### Caching Strategy

- 24-hour default cache TTL for IOC results
- Force refresh option available
- Intelligent cache invalidation
- Reduced API calls through smart caching

##  Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -m 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a pull request

##  Roadmap

- [ ] Real-time WebSocket updates for long-running analyses
- [ ] Advanced visualization with threat correlation graphs
- [ ] MISP integration for threat intelligence sharing
- [ ] Multi-tenant support with user authentication
- [ ] Advanced export formats (STIX/TAXII)
- [ ] Automated IOC collection from feeds
- [ ] Machine learning-based threat scoring
- [ ] API rate limiting per user/tenant

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Support

- **Documentation**: Check this README and inline code comments
- **Issues**: GitHub Issues for bug reports and feature requests
- **Security**: Report security vulnerabilities privately

---

**Forensic Cyber Tech | EagleEye Platform**
*Advanced Threat Intelligence & IOC Analysis*
