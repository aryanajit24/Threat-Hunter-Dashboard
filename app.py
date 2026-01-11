from flask import Flask, render_template, request as flask_request, jsonify
import requests
from datetime import datetime
import os

app = Flask(__name__)

# API Keys (we'll set these up later)
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY', '')
VT_KEY = os.getenv('VT_KEY', '')

class ThreatIntelligence:
    def check_ip_abuseipdb(self, ip):
        """Check IP reputation on AbuseIPDB"""
        if not ABUSEIPDB_KEY:
            return {'error': 'AbuseIPDB API key not configured'}
        
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_KEY
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    'ip': ip,
                    'abuse_score': data.get('abuseConfidenceScore', 0),
                    'country': data.get('countryCode', 'Unknown'),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt', 'Never'),
                    'isp': data.get('isp', 'Unknown')
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def check_ip_virustotal(self, ip):
        """Check IP on VirusTotal"""
        if not VT_KEY:
            return {'error': 'VirusTotal API key not configured'}
        
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {'x-apikey': VT_KEY}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()['data']['attributes']
                stats = data.get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'reputation': data.get('reputation', 0)
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def get_ip_info(self, ip):
        """Get basic IP info from free API"""
        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=10)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {}
    
    def analyze_threat(self, ip):
        """Comprehensive threat analysis"""
        result = {
            'ip': ip,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'threat_level': 'Unknown',
            'threat_score': 0
        }
        
        # Get basic IP info (always works, no API key needed)
        ip_info = self.get_ip_info(ip)
        if ip_info:
            result['ip_info'] = ip_info
        
        # Check AbuseIPDB
        abuse_data = self.check_ip_abuseipdb(ip)
        result['abuseipdb'] = abuse_data
        
        if 'error' not in abuse_data:
            score = abuse_data.get('abuse_score', 0)
            if score > 75:
                result['threat_level'] = 'Critical'
            elif score > 50:
                result['threat_level'] = 'High'
            elif score > 25:
                result['threat_level'] = 'Medium'
            else:
                result['threat_level'] = 'Low'
        
        # Check VirusTotal
        vt_data = self.check_ip_virustotal(ip)
        result['virustotal'] = vt_data
        
        if 'error' not in vt_data and vt_data.get('malicious', 0) > 5:
            result['threat_level'] = 'Critical'
        
        return result

ti = ThreatIntelligence()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_ip', methods=['POST'])
def check_ip():
    ip = flask_request.form.get('ip', '').strip()
    
    if not ip:
        return '<h1>Error: No IP provided</h1><a href="/">Go Back</a>'
    
    # Basic IP validation
    parts = ip.split('.')
    if len(parts) != 4:
        return '<h1>Error: Invalid IP format</h1><a href="/">Go Back</a>'
    
    result = ti.analyze_threat(ip)
    return render_template('result.html', result=result)

@app.route('/test')
def test():
    """Test route to verify Flask is working"""
    return '<h1>✅ Flask is working!</h1><a href="/">Go to home</a>'

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Threat Hunter Dashboard Starting...")
    print("📍 Access at: http://localhost:5000")
    print("🧪 Test page: http://localhost:5000/test")
    if not ABUSEIPDB_KEY and not VT_KEY:
        print("⚠️  WARNING: No API keys configured")
        print("   Basic IP lookup will still work!")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)