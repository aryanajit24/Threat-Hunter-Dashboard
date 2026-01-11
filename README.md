# 🔍 Threat Hunter Dashboard

A multi-source threat intelligence platform that aggregates IP reputation data from AbuseIPDB, VirusTotal, and geolocation APIs.

## 🎯 Overview
This project demonstrates practical SOC analyst skills by integrating multiple threat intelligence APIs into a unified dashboard. Built for security professionals and students learning cybersecurity.

## Key Features

- ✅ Multi-Source Intelligence: AbuseIPDB, VirusTotal, and IPAPI geolocation
- ✅ Real-Time Analysis: Instant IP reputation checking
- ✅ Threat Scoring: Automated threat level assessment (Critical/High/Medium/Low)
- ✅ Abuse Confidence Scoring: Community-driven abuse reports
- ✅ Malware Detection: 70+ security vendor detections via VirusTotal
- ✅ Geolocation Tracking: ISP, country, city, and ASN information
- ✅ Clean UI: Responsive, modern interface

## 🛠️ Tech Stack

**Backend:**
- Python 3.8+
- Flask 3.0
- Requests library

**APIs:**
- AbuseIPDB API (IP abuse reports)
- VirusTotal API v3 (malware detection)
- IPAPI (geolocation data)

**Frontend:**
- HTML5
- CSS3 (responsive design)
- No JavaScript frameworks (pure HTML/CSS)

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- API keys (free tier available):
  - AbuseIPDB - 1000 checks/day
  - VirusTotal - 4 requests/minute

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/aryanajit24/Threat-Hunter-Dashboard.git
cd Threat-Hunter-Dashboard
```

### 2. Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure API Keys
Create a `.env` file in the project root:
```bash
ABUSEIPDB_KEY=your_abuseipdb_api_key_here
VT_KEY=your_virustotal_api_key_here
```

**Getting API Keys:**

**AbuseIPDB:**
1. Register at https://www.abuseipdb.com/register
2. Go to Account → API → Create Key
3. Copy key to .env file

**VirusTotal:**
1. Register at https://www.virustotal.com/gui/join-us
2. Click your profile icon → API Key
3. Copy key to .env file

### 5. Run the Application
```bash
python3 app.py
```

Access the dashboard at: **http://localhost:5000**

## 📖 Usage

1. Open the dashboard in your web browser
2. Enter an IP address in the search box (e.g., 8.8.8.8)
3. Click "Analyze Threat" to run the analysis
4. Review results across multiple threat intelligence sources

**Example IPs to Test:**
- `8.8.8.8` - Google DNS (should be clean)
- `1.1.1.1` - Cloudflare DNS (should be clean)
- Check AbuseIPDB for known malicious IPs to test

## 🔍 Features in Detail

### Threat Level Assessment
The dashboard automatically calculates threat levels based on:

- **Critical (Red)**: Abuse score > 75% OR 5+ malicious detections
- **High (Orange)**: Abuse score 50-75%
- **Medium (Yellow)**: Abuse score 25-50%
- **Low (Green)**: Abuse score < 25%
- **Unknown (Gray)**: Insufficient data

### Data Sources

**AbuseIPDB:**
- Abuse confidence score (0-100%)
- Total abuse reports
- Last reported date
- Country and ISP information

**VirusTotal:**
- Malicious detections count
- Suspicious detections
- Harmless assessments
- Community reputation score

**Geolocation (IPAPI):**
- Country, region, city
- ISP/Organization
- ASN (Autonomous System Number)
- Timezone

## 📁 Project Structure

```
threat-hunter/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env                   # API keys (not tracked in git)
├── .gitignore            # Files to exclude from git
├── README.md             # This file
├── templates/
│   ├── index.html        # Homepage
│   └── result.html       # Results page
└── screenshots/          # Screenshots for documentation
    ├── homepage.png
    ├── analysis.png
    └── results.png
```

## 🔒 Security Notes

- ⚠️ **Never commit .env file** - It contains your API keys
- API keys in .env are automatically ignored by git via .gitignore
- Use read-only API keys when possible
- Rate limits: AbuseIPDB (1000/day), VirusTotal (4/min)

## 🛣️ Roadmap / Future Enhancements

- [ ] Bulk IP scanning (CSV upload)
- [ ] Historical tracking and trends
- [ ] Export reports (PDF/JSON)
- [ ] Additional threat intel sources (AlienVault OTX, Shodan)
- [ ] Database storage for analysis history
- [ ] API endpoint for programmatic access
- [ ] Docker containerization
- [ ] Automated scheduled scans

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👤 Author

**Aryan Panicker**
- 🎓 Constructor University Bremen
- 💼 [LinkedIn](https://www.linkedin.com/in/aryan-panicker-0856a0203/)
- 🐙 [GitHub](https://github.com/aryanajit24)
- 📧 apanicker@constructor.university

## 🙏 Acknowledgments

- AbuseIPDB for IP abuse data
- VirusTotal for malware detection
- IPAPI for geolocation services
- Constructor University for providing learning resources

## 📚 Learning Resources

This project was built as part of SOC analyst training. Recommended resources:
- [TryHackMe SOC Level 1](https://tryhackme.com)
- [LetsDefend](https://letsdefend.io)
- [AbuseIPDB Documentation](https://docs.abuseipdb.com)
- [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview)

## ⚠️ Disclaimer

This tool is for educational and legitimate security research purposes only. Always ensure you have proper authorization before scanning IP addresses. Misuse of this tool for malicious purposes is strictly prohibited and may be illegal.

---

⭐ **If you find this project useful, please consider giving it a star!**

📧 **Questions or feedback? Open an issue or reach out!