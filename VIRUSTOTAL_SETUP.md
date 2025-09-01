# Real-time VirusTotal Integration Setup

## VirusTotal API Key Configuration

To enable real-time VirusTotal data fetching, you need to:

1. **Get a VirusTotal API Key:**
   - Go to [VirusTotal API](https://www.virustotal.com/gui/join-us)
   - Sign up for a free account
   - Go to your profile and copy your API key

2. **Configure Environment Variables:**
   - Open `.env.local` file in the project root
   - Replace `your_virustotal_api_key_here` with your actual API key:
   ```
   VT_API_KEY=your_actual_virustotal_api_key_here
   ```

3. **API Rate Limits:**
   - Free accounts: 4 requests per minute
   - Premium accounts: Higher limits available

## Features

- **Real-time Data**: Fetches live data from VirusTotal API
- **Comprehensive Analysis**: File information, threat classification, sandbox analysis
- **Engine Results**: Detailed results from multiple antivirus engines
- **Performance Metrics**: Engine performance analysis and visualizations
- **Auto-refresh**: Manual refresh button for latest data
- **Error Handling**: Graceful fallback when API is unavailable

## Testing

1. Start the development server: `npm run dev`
2. Navigate to the analyze page
3. Enter a hash IOC (SHA256, MD5, or SHA1)
4. Click "Hunt" to analyze
5. Switch to "File Analysis Results" tab to see real-time data

## Sample Test Hashes

You can test with these known malicious hashes:
- `8d24d4e72b7b22017c6d6e7b1a2dc1a1ead63b97b58114c02c221aa86dd9d00c`
- `cf6eb0ac5cd413d93bef403f`
