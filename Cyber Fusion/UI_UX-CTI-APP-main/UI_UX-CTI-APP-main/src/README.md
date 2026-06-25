# 🛡️ Cyber Threat Intelligence Platform

A comprehensive, production-ready threat intelligence analysis platform built with React, TypeScript, Tailwind CSS, and Supabase.

## 🌟 Features

### ⚡ Unified Intelligent Threat Analysis
- **Auto-Detection**: Automatically identifies IP addresses, domains, URLs, file hashes, subnets, and ASN numbers
- **Multi-Source Analysis**: Correlates data from VirusTotal and AbuseIPDB
- **AI-Powered Reports**: Generates comprehensive threat assessments using Qwen AI
- **5-Dimensional Scoring**: Analyzes threats across Malware, Reputation, Network, Geographic, and History dimensions

### 📊 Rich Visualizations
- **Threat Level Indicators**: Color-coded CRITICAL/HIGH/MEDIUM/LOW ratings
- **Interactive Charts**: Pie charts, bar charts, and radar plots
- **Vendor Analysis**: Detailed table of security vendor detections
- **Progress Indicators**: Visual abuse confidence scoring

### 🎯 Advanced Features
- **Threat Correlation Engine**: Cross-references multiple threat intelligence sources
- **Priority-Based Mitigation**: Automatically generated actionable security recommendations
- **Download Reports**: Export analyses as PDF or DOCX
- **Analysis History**: Track and re-download previous reports
- **Complete Documentation**: Interactive flowcharts and database diagrams

### 🔐 Security & Authentication
- **Supabase Authentication**: Secure JWT-based auth system
- **Email/Password**: Traditional authentication
- **Google OAuth**: Social login (configurable)
- **Session Management**: Persistent, secure sessions
- **Row-Level Security**: Users only access their own data

## 🚀 Quick Start

### 1. Prerequisites
- Supabase account and project
- API keys for:
  - [VirusTotal](https://www.virustotal.com/gui/my-apikey)
  - [AbuseIPDB](https://www.abuseipdb.com/account/api)
  - [Qwen AI](https://dashscope.aliyun.com/)

### 2. Set API Keys
In Supabase Dashboard → Settings → Edge Functions, add:
```
VIRUSTOTAL_API_KEY
ABUSEIPDB_API_KEY
QWEN_API_KEY
```

### 3. Create Test User (Optional)
```bash
POST https://YOUR_PROJECT.supabase.co/functions/v1/make-server-4d23e959/create-test-user
```
Creates: `test@example.com` / `test123456`

### 4. Start Using
1. Sign up with any email or use test account
2. Login to access the dashboard
3. Enter any threat indicator
4. Get comprehensive analysis results!

## 📁 Project Structure

```
/
├── App.tsx                           # Main application component
├── components/
│   ├── DashboardPage.tsx             # Unified threat analysis
│   ├── HistoryPage.tsx               # Download history
│   ├── SettingsPage.tsx              # User settings
│   ├── DocumentationPage.tsx         # System documentation
│   ├── LoginPage.tsx                 # Authentication
│   ├── SignupPage.tsx                # User registration
│   ├── ComprehensiveFlowchart.tsx    # Complete system flowchart
│   ├── ComprehensiveERD.tsx          # Database entity diagram
│   └── ui/                           # Reusable UI components
├── supabase/
│   └── functions/
│       ├── make-server-4d23e959/     # Main Edge Function
│       │   └── index.tsx
│       └── server/                   # Shared modules
│           ├── kv_store.tsx          # Key-value storage
│           └── threat-analysis.tsx   # API integrations
├── styles/
│   └── globals.css                   # Global styles
└── utils/
    └── supabase/                     # Supabase client config
```

## 🎯 Supported Indicators

The platform automatically detects and analyzes:

| Type | Example | Auto-Detected |
|------|---------|---------------|
| IPv4 | `8.8.8.8` | ✅ |
| IPv6 | `2001:4860:4860::8888` | ✅ |
| Domain | `google.com` | ✅ |
| URL | `https://example.com/path` | ✅ |
| MD5 Hash | `5d41402abc4b2a76b9719d911017c592` | ✅ |
| SHA1 Hash | `2fd4e1c67a2d28fced849ee1bb76e7391b93eb12` | ✅ |
| SHA256 Hash | `2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae` | ✅ |
| Subnet | `192.168.1.0/24` | ✅ |
| ASN | `AS15169` | ✅ |

## 📊 Analysis Results

Each analysis provides:

1. **Threat Level** - Overall risk assessment
2. **Total Alerts** - Number of security vendors reporting
3. **High Alerts** - Malicious detections count
4. **Medium Alerts** - Suspicious detections count
5. **Threat Distribution** - Visual breakdown by category
6. **Detection Statistics** - Vendor analysis charts
7. **Security Vendor Analysis** - Detailed vendor table
8. **IP Reputation** - AbuseIPDB data (for IP indicators)
9. **AI-Generated Report** - Comprehensive threat assessment
10. **Threat Correlation** - Multi-dimensional analysis with radar chart
11. **Mitigation Actions** - Prioritized security recommendations

## 🔌 API Endpoints

All endpoints are prefixed with `/make-server-4d23e959/`:

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/create-test-user` | POST | No | Create test account |
| `/unified-analyze` | POST | Yes | Main analysis endpoint |
| `/analyze` | POST | Yes | Legacy analysis |
| `/abuse-check` | POST | Yes | AbuseIPDB check |
| `/history` | POST | Yes | Save download |
| `/history` | GET | Yes | Get downloads |

## 🗄️ Database Schema

### Core Entities
- **USERS** - User accounts and profiles
- **ROLES** - Permission management
- **ANALYSIS_REQUESTS** - Analysis jobs
- **INDICATORS** - Threat indicators (IPs, domains, etc.)
- **VIRUSTOTAL_RESULTS** - VT API responses
- **ABUSEIPDB_RESULTS** - AbuseIPDB API responses
- **THREAT_SCORES** - Calculated threat levels
- **VENDOR_DETECTIONS** - Individual vendor results
- **AI_REPORTS** - AI-generated analyses
- **CORRELATION_RESULTS** - Cross-source insights
- **MITIGATION_RECOMMENDATIONS** - Security actions
- **ALERTS** - User notifications
- **DOWNLOAD_HISTORY** - Report downloads
- **ACTIVITY_LOGS** - Audit trail

## 🎨 UI/UX Highlights

- **Responsive Design**: Works on mobile, tablet, and desktop
- **Dark Mode Support**: Automatic theme detection
- **Touch-Friendly**: Optimized for mobile devices
- **Real-Time Feedback**: Auto-detection badges and loading states
- **Accessible**: WCAG-compliant components
- **Professional**: Clean, modern design

## 📚 Documentation

Comprehensive guides included:

- **QUICK_START.md** - Get started in 5 minutes
- **DEPLOYMENT_FIX.md** - Edge Function deployment guide
- **AUTHENTICATION_GUIDE.md** - Login/signup documentation
- **UNIFIED_ANALYSIS_UPDATE.md** - Complete feature documentation
- **FIXES_APPLIED.md** - Bug fixes and solutions

## 🔒 Security Features

- ✅ JWT authentication
- ✅ Row-level security policies
- ✅ Secure password hashing
- ✅ CORS protection
- ✅ Input sanitization
- ✅ Rate limiting ready
- ✅ Audit logging
- ✅ Session management

## 🚧 Future Enhancements

- [ ] Bulk indicator analysis
- [ ] Automated threat hunting
- [ ] SOAR platform integration
- [ ] Custom correlation rules
- [ ] ML threat prediction
- [ ] Real-time alerts
- [ ] Advanced filtering
- [ ] Threat actor attribution
- [ ] Campaign tracking
- [ ] Collaborative features

## 🤝 Contributing

This is a complete, production-ready platform. To extend:

1. Add new threat intelligence sources in `threat-analysis.tsx`
2. Create new visualizations in component files
3. Extend database schema as needed
4. Add new analysis types in the unified analyzer

## 📄 License

This project is built as a comprehensive threat intelligence platform demonstration.

## 🙏 Acknowledgments

Built with:
- [React](https://react.dev/) - UI framework
- [TypeScript](https://www.typescriptlang.org/) - Type safety
- [Tailwind CSS](https://tailwindcss.com/) - Styling
- [Supabase](https://supabase.com/) - Backend & Auth
- [Recharts](https://recharts.org/) - Data visualization
- [VirusTotal](https://www.virustotal.com/) - Malware intelligence
- [AbuseIPDB](https://www.abuseipdb.com/) - IP reputation
- [Qwen AI](https://dashscope.aliyun.com/) - AI analysis

## 📞 Support

For issues or questions:
1. Check the documentation files
2. Review browser console logs
3. Check Supabase Edge Function logs
4. Verify API keys are set correctly

## ✨ Status

🟢 **Fully Functional** - All features working
- ✅ Authentication system
- ✅ Unified threat analysis
- ✅ Multi-source correlation
- ✅ AI-powered reports
- ✅ Download capabilities
- ✅ Complete documentation

---

**Built with ❤️ for cybersecurity professionals**

Start analyzing threats today! 🛡️🔍
