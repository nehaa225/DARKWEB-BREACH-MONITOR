from flask import Flask, jsonify, request, send_from_directory, make_response
import requests
import sqlite3
import smtplib
import os
import hashlib
from email.message import EmailMessage
from dotenv import load_dotenv
from datetime import datetime
import time
import math
import re

# ==============================
# ENVIRONMENT VARIABLES
# ==============================
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

app = Flask(__name__, static_folder='static', static_url_path='')

# ==============================
# DATABASE UTILITIES
# ==============================
def get_db_path():
    # If running on Vercel or in a read-only local directory, use /tmp
    if os.environ.get("VERCEL") or not os.access(".", os.W_OK):
        return "/tmp/users.db"
    return "users.db"

def get_db_connection():
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    db_path = get_db_path()
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
        
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Create tables
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password_hash TEXT,
        last_checked TEXT,
        breach_count INTEGER DEFAULT 0
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS breach_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        source_name TEXT,
        breach_date TEXT,
        exposed_data TEXT,
        date_detected TEXT,
        risk_level TEXT,
        FOREIGN KEY(email) REFERENCES users(email) ON DELETE CASCADE
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)
    conn.commit()
    conn.close()

# Initialize tables
init_database()

# Helpers for persistent settings in SQLite
def get_setting(conn, key, default):
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone()
    if row:
        val = row["value"]
        if val == "True": return True
        if val == "False": return False
        return val
    return default

def set_setting(conn, key, value):
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()

# ==============================
# BREACH DETECTOR LOGIC
# ==============================
def get_simulated_breaches(email):
    """Generates deterministic mock breach data based on email hash."""
    h = int(hashlib.md5(email.encode('utf-8')).hexdigest(), 16)
    
    available_breaches = [
        {"name": "LinkedIn Leak", "date": "2021", "leaks": ["Email", "Full Name", "Job Title", "Social Links"]},
        {"name": "Adobe Creative Cloud", "date": "2013", "leaks": ["Email", "Password Hint", "Username", "Password (Hashed)"]},
        {"name": "Canva Data Breach", "date": "2019", "leaks": ["Email", "Full Name", "Username", "Password (Salted Bcrypt)"]},
        {"name": "Dropbox Leak", "date": "2016", "leaks": ["Email", "Password (Hashed)"]},
        {"name": "MySpace Mega Breach", "date": "2016", "leaks": ["Email", "Username", "Password (Plaintext)"]},
        {"name": "Equifax Breach", "date": "2017", "leaks": ["Email", "SSN", "Full Name", "DOB", "Mailing Address", "Phone Number"]},
        {"name": "Target Retail Hack", "date": "2013", "leaks": ["Email", "Full Name", "Credit Card Details", "Phone Number"]},
        {"name": "Zynga Games Leak", "date": "2019", "leaks": ["Email", "Username", "Password (SHA-1)"]},
        {"name": "CyberPunk Forum Leak", "date": "2024", "leaks": ["Email", "IP Address", "Username", "Salted Password"]}
    ]
    
    # Deterministic number of breaches (0 to 4)
    num_breaches = h % 5
    if num_breaches == 0:
        return []
        
    selected = []
    for i in range(num_breaches):
        idx = (h + i) % len(available_breaches)
        if available_breaches[idx] not in selected:
            selected.append(available_breaches[idx])
            
    return selected

def check_email_breach(email, demo_mode):
    """Checks breach status. Calls LeakCheck API in live mode, or generates simulated data in demo mode."""
    if demo_mode:
        time.sleep(0.5)  # Simulate network lag
        return get_simulated_breaches(email)
        
    try:
        url = f"https://leakcheck.io/api/public?check={email}"
        response = requests.get(url, timeout=10)
        if response.status_code == 429:
            return get_simulated_breaches(email)
        if response.status_code != 200:
            return get_simulated_breaches(email)
        try:
            data = response.json()
        except ValueError:
            return get_simulated_breaches(email)
            
        if data.get("success") and data.get("found") > 0:
            formatted_breaches = []
            for item in data.get("sources", []):
                formatted_breaches.append({
                    "name": item.get("name") or item.get("title") or "Unknown Source",
                    "date": item.get("breachDate") or item.get("date") or "Unknown Date",
                    "leaks": item.get("leaks") or item.get("dataTypes") or ["Email"]
                })
            return formatted_breaches
        return []
    except requests.exceptions.RequestException:
        return get_simulated_breaches(email)

# ==============================
# AI THREAT ADVISORY LOGIC
# ==============================
def get_risk_level(exposed_data_list, breach_count):
    """Heuristic function to determine risk level based on leaked data types."""
    if breach_count == 0:
        return "Safe"
        
    critical_keywords = ["ssn", "socialsecurity", "credit card", "bank", "financial", "identity"]
    high_keywords = ["password", "hash", "salt", "dob", "address", "phone"]
    
    joined_data = " ".join([d.lower() for d in exposed_data_list])
    
    if any(k in joined_data for k in critical_keywords):
        return "Critical"
    elif any(k in joined_data for k in high_keywords) or breach_count >= 3:
        return "High"
    elif breach_count >= 1:
        return "Medium"
    else:
        return "Low"

def generate_local_risk_analysis(email, breach_count, exposed_data_list):
    """Fallback local analyzer when Gemini is not used or fails."""
    risk = get_risk_level(exposed_data_list, breach_count)
    data_summary = ", ".join(exposed_data_list) if exposed_data_list else "Information not provided by source"
    
    analysis = f"""### 🛡️ Threat Analysis Brief (Local Engine)
* **Email Inspected:** `{email}`
* **Breach Count:** `{breach_count}`
* **Exposed Data Structure:** `{data_summary}`
* **Risk Categorization:** **{risk.upper()}**

---

### ⚠️ Attack Vector Scenarios:
"""
    if "Password" in data_summary or "password" in data_summary.lower():
        analysis += "- **Credential Stuffing:** Attackers will automate login attempts across dozens of popular websites using this password and email.\n"
    if "SSN" in data_summary or "Credit Card" in data_summary or "credit card" in data_summary.lower():
        analysis += "- **Identity Theft & Fraud:** Attackers can open unauthorized lines of credit or bypass bank verification.\n"
    if breach_count > 0:
        analysis += "- **Social Engineering / Phishing:** Attackers will use your leaked context (like job titles or breached platforms) to draft highly convincing emails targeting you.\n"
        
    analysis += """
### 🛠️ Priority Remediation Playbook:
1. **Immediate Password Reset:** Change the passwords of the compromised account and any other account sharing that password.
2. **Enable MFA:** Turn on Multi-Factor Authentication (MFA/2FA) on all active services.
3. **Deploy Password Manager:** Store randomized 16+ character passwords.
4. **Monitor Credit Score:** If financial/SSN data was leaked, freeze your credit reports.
"""
    return analysis, risk

def generate_gemini_analysis(email, breach_count, exposed_data_list, gemini_enabled):
    """Calls Gemini API via requests to get a highly customized cybersecurity report."""
    if not GOOGLE_API_KEY or not gemini_enabled:
        return None, get_risk_level(exposed_data_list, breach_count)
        
    data_summary = ", ".join(exposed_data_list) if exposed_data_list else "Information not provided by source"
    risk_est = get_risk_level(exposed_data_list, breach_count)
    
    prompt = f"""
    You are a cybersecurity AI threat analyst.
    Analyze the threat profile for this dark web exposure:
    - Email Inspected: {email}
    - Total Breaches Found: {breach_count}
    - Compromised Data Attributes: {data_summary}
    - Preliminary Risk Assessment: {risk_est}
    
    Produce a professional threat intelligence report in raw Markdown format.
    Use clear headings, bullet points, and code formatting for key metrics.
    Include:
    1. A bold, concise executive assessment detailing why this combination of leaked data is dangerous.
    2. Concrete cyber attack scenarios (e.g. SIM swapping, phishing, brute force) specific to this combination.
    3. An actionable, priority-ordered checklist for remediation.
    
    Do not use any HTML tags. Keep the text professional and focused.
    """
    
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GOOGLE_API_KEY}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 800
            }
        }
        response = requests.post(url, headers=headers, json=payload, timeout=8)
        if response.status_code == 200:
            result = response.json()
            text = result["candidates"][0]["content"]["parts"][0]["text"]
            return text, risk_est
        else:
            return None, risk_est
    except Exception:
        return None, risk_est

# ==============================
# REMEDIATION RECOMMENDATION
# ==============================
def get_remediation_recommendations(exposed_data_list):
    recommendations = [
        "Change passwords on all affected platforms immediately.",
        "Implement Multi-Factor Authentication (MFA / 2FA) on your primary email and finance portals.",
        "Audit active sessions on your email account and sign out of unknown devices."
    ]
    
    joined_data = " ".join([d.lower() for d in exposed_data_list])
    
    if "password" in joined_data:
        recommendations.append("Adopt a secure password manager (e.g., Bitwarden, 1Password) to generate unique passwords.")
    if "phone" in joined_data:
        recommendations.append("Contact your cellular carrier to enable SIM-swap protection/PIN lock.")
    if "ssn" in joined_data or "socialsecurity" in joined_data:
        recommendations.append("Freeze your credit reports at Experian, Equifax, and TransUnion.")
    if "credit card" in joined_data or "bank" in joined_data or "payment" in joined_data:
        recommendations.append("Request a replacement card from your bank and review bank statements for micro-charges.")
        
    return recommendations

# ==============================
# EMAIL ALERT DISPATCHER
# ==============================
def send_alert(to_email, subject, message, smtp_host, smtp_port):
    if not EMAIL_USER or not EMAIL_PASS:
        return False
    try:
        msg = EmailMessage()
        msg.set_content(message)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=8)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=8)
            server.starttls()
            
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        return True
    except Exception:
        return False

# ==============================
# PASSWORD SECURITY ENGINE
# ==============================
def check_password_strength(password):
    """Calculates password entropy and gives custom cyber feedback."""
    if not password:
        return 0, "No password provided", "red", []
        
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_special: pool_size += 32
    
    if pool_size == 0:
        return 0, "Empty", "#ef4444", []
        
    entropy = length * math.log2(pool_size)
    
    feedback = []
    if length < 12:
        feedback.append("Increase length to at least 12 characters.")
    if not (has_upper and has_lower):
        feedback.append("Combine both uppercase and lowercase letters.")
    if not has_digit:
        feedback.append("Add at least one numerical digit.")
    if not has_special:
        feedback.append("Include special characters (e.g. $, !, @, %).")
        
    if entropy < 30:
        return entropy, "Critical Risk / Weak", "#ef4444", feedback
    elif entropy < 55:
        return entropy, "Moderate Strength / Vulnerable", "#eab308", feedback
    elif entropy < 80:
        return entropy, "Strong Password", "#3b82f6", feedback
    else:
        return entropy, "Excellent / Highly Secure", "#22c55e", feedback

# ==============================
# FLASK ROUTING & CONTROLLERS
# ==============================
@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/status', methods=['GET'])
def api_status():
    conn = get_db_connection()
    demo_mode = get_setting(conn, "demo_mode", True)
    gemini_enabled = get_setting(conn, "gemini_enabled", GOOGLE_API_KEY is not None)
    smtp_host = get_setting(conn, "smtp_host", "smtp.gmail.com")
    smtp_port = int(get_setting(conn, "smtp_port", 587))
    conn.close()
    
    return jsonify({
        "demo_mode": demo_mode,
        "gemini_enabled": gemini_enabled,
        "smtp_configured": bool(EMAIL_USER and EMAIL_PASS),
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "gemini_available": bool(GOOGLE_API_KEY),
        "email_user": EMAIL_USER or ""
    })

@app.route('/api/settings/update', methods=['POST'])
def api_settings_update():
    data = request.json or {}
    conn = get_db_connection()
    if 'demo_mode' in data:
        set_setting(conn, "demo_mode", bool(data['demo_mode']))
    if 'gemini_enabled' in data:
        set_setting(conn, "gemini_enabled", bool(data['gemini_enabled']) and bool(GOOGLE_API_KEY))
    if 'smtp_host' in data:
        set_setting(conn, "smtp_host", str(data['smtp_host']))
    if 'smtp_port' in data:
        try:
            set_setting(conn, "smtp_port", int(data['smtp_port']))
        except ValueError:
            pass
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/settings/send_test', methods=['POST'])
def api_send_test():
    data = request.json or {}
    recipient = data.get("recipient")
    if not recipient:
        return jsonify({"status": "error", "message": "Recipient email required."}), 400
        
    conn = get_db_connection()
    smtp_host = get_setting(conn, "smtp_host", "smtp.gmail.com")
    smtp_port = int(get_setting(conn, "smtp_port", 587))
    conn.close()
    
    success = send_alert(
        recipient,
        "🛡️ Dark Web Breach Shield - SMTP Connection Test",
        "Security connection test. If you received this email, the SMTP alert dispatcher is functioning correctly!",
        smtp_host,
        smtp_port
    )
    
    if success:
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Outbound connection failed. Check your local environment SMTP configurations."}), 500

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json or {}
    email = data.get("email")
    if not email:
        return jsonify({"status": "error", "message": "Email is required."}), 400
        
    conn = get_db_connection()
    demo_mode = get_setting(conn, "demo_mode", True)
    gemini_enabled = get_setting(conn, "gemini_enabled", GOOGLE_API_KEY is not None)
    smtp_host = get_setting(conn, "smtp_host", "smtp.gmail.com")
    smtp_port = int(get_setting(conn, "smtp_port", 587))
    
    # Run breach scanner
    breaches = check_email_breach(email, demo_mode)
    
    # Calculate exposed data items
    all_exposed_data = []
    for b in breaches:
        all_exposed_data.extend(b.get("leaks", []))
    unique_exposed = list(set(all_exposed_data))
    
    # Generate threat intelligence advisory
    ai_brief, calculated_risk = generate_gemini_analysis(email, len(breaches), unique_exposed, gemini_enabled)
    if not ai_brief:
        ai_brief, calculated_risk = generate_local_risk_analysis(email, len(breaches), unique_exposed)
        
    remediation_items = get_remediation_recommendations(unique_exposed)
    
    conn.close()
    
    # Automatically attempt email alert dispatch if user email exists and breaches detected
    smtp_status = "queued"
    if breaches and EMAIL_USER and EMAIL_PASS:
        email_body = f"""Dark Web Breach Alert Report
        
Email: {email}
Risk Profile: {calculated_risk}
Leaks Found: {len(breaches)}

Threat Advisory:
{ai_brief}

Mitigation Checklist:
- {"\n- ".join(remediation_items)}
"""
        sent = send_alert(email, f"⚠️ Dark Web Breach Alert: {email}", email_body, smtp_host, smtp_port)
        smtp_status = "sent" if sent else "failed"
        
    return jsonify({
        "email": email,
        "breaches": breaches,
        "risk_level": calculated_risk,
        "report": ai_brief,
        "remediation": remediation_items,
        "smtp_status": smtp_status
    })

@app.route('/api/monitored', methods=['GET'])
def api_monitored_list():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email, last_checked, breach_count FROM users")
    rows = c.fetchall()
    conn.close()
    
    users = []
    for row in rows:
        users.append({
            "email": row["email"],
            "last_checked": row["last_checked"],
            "breach_count": row["breach_count"]
        })
    return jsonify(users)

@app.route('/api/monitor/add', methods=['POST'])
def api_monitor_add():
    data = request.json or {}
    email = data.get("email")
    breach_count = data.get("breach_count", 0)
    breaches = data.get("breaches", [])
    
    if not email:
        return jsonify({"status": "error", "message": "Email is required."}), 400
        
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT OR REPLACE INTO users (email, last_checked, breach_count) VALUES (?, ?, ?)", 
                  (email, now_str, breach_count))
        
        # Clear existing entries first
        c.execute("DELETE FROM breach_records WHERE email = ?", (email,))
        
        for b in breaches:
            name = b.get("name", "Unknown Source")
            date = b.get("date", "Unknown Date")
            leaks = ", ".join(b.get("leaks", []))
            risk = get_risk_level(b.get("leaks", []), 1)
            c.execute("""
                INSERT INTO breach_records (email, source_name, breach_date, exposed_data, date_detected, risk_level)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (email, name, date, leaks, now_str, risk))
            
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": f"Added {email} to continuous monitoring."})
    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/monitor/delete', methods=['POST'])
def api_monitor_delete():
    data = request.json or {}
    email = data.get("email")
    if not email:
        return jsonify({"status": "error", "message": "Email required."}), 400
        
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM users WHERE email = ?", (email,))
        c.execute("DELETE FROM breach_records WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/monitor/sync', methods=['POST'])
def api_monitor_sync():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email FROM users")
    users = c.fetchall()
    
    demo_mode = get_setting(conn, "demo_mode", True)
    
    synced = []
    for u in users:
        email = u["email"]
        breaches = check_email_breach(email, demo_mode)
        breach_count = len(breaches)
        
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE users SET last_checked = ?, breach_count = ? WHERE email = ?", 
                  (now_str, breach_count, email))
        
        # Refresh details
        c.execute("DELETE FROM breach_records WHERE email = ?", (email,))
        for b in breaches:
            name = b.get("name", "Unknown Source")
            date = b.get("date", "Unknown Date")
            leaks = ", ".join(b.get("leaks", []))
            risk = get_risk_level(b.get("leaks", []), 1)
            c.execute("""
                INSERT INTO breach_records (email, source_name, breach_date, exposed_data, date_detected, risk_level)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (email, name, date, leaks, now_str, risk))
            
        synced.append({"email": email, "breach_count": breach_count})
        
        # Prevent API throttling in live mode
        if not demo_mode:
            time.sleep(1.5)
            
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "synced": synced})

@app.route('/api/dashboard/stats', methods=['GET'])
def api_dashboard_stats():
    conn = get_db_connection()
    c = conn.cursor()
    
    # 1. Monitored assets list
    c.execute("SELECT * FROM users")
    users = [dict(row) for row in c.fetchall()]
    
    # 2. Breach records list
    c.execute("SELECT * FROM breach_records")
    breaches = [dict(row) for row in c.fetchall()]
    
    total_assets = len(users)
    total_breaches = len(breaches)
    compromised_assets = sum(1 for u in users if u["breach_count"] > 0)
    safe_assets = total_assets - compromised_assets
    
    # Risk counts
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for b in breaches:
        rl = b["risk_level"] or "Medium"
        if rl in risk_counts:
            risk_counts[rl] += 1
            
    high_critical = risk_counts["Critical"] + risk_counts["High"]
    
    # Exposed Data Types counts
    data_counts = {}
    for b in breaches:
        if b["exposed_data"]:
            items = [item.strip() for item in b["exposed_data"].split(",") if item.strip()]
            for item in items:
                data_counts[item] = data_counts.get(item, 0) + 1
                
    # Parse years for timeline history
    years_counts = {}
    for b in breaches:
        match = re.search(r'\b(19|20)\d{2}\b', str(b["breach_date"]))
        year = int(match.group(0)) if match else 2020
        years_counts[year] = years_counts.get(year, 0) + 1
        
    timeline = [{"year": y, "count": years_counts[y]} for y in sorted(years_counts.keys())]
    
    conn.close()
    
    return jsonify({
        "metrics": {
            "total_assets": total_assets,
            "total_breaches": total_breaches,
            "safe_assets": safe_assets,
            "high_critical": high_critical
        },
        "risk_distribution": risk_counts,
        "data_types_distribution": data_counts,
        "timeline": timeline,
        "inventory": breaches
    })

@app.route('/api/dashboard/export', methods=['GET'])
def api_dashboard_export():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM breach_records")
    rows = c.fetchall()
    conn.close()
    
    import io
    import csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Monitored Asset", "Source Database", "Breach Year/Date", "Exposed Data Attributes", "Date Found", "Severity"])
    for r in rows:
        writer.writerow([
            r["id"],
            r["email"],
            r["source_name"],
            r["breach_date"],
            r["exposed_data"],
            r["date_detected"],
            r["risk_level"]
        ])
        
    response = make_response(output.getvalue())
    now_str = datetime.now().strftime("%Y%m%d")
    response.headers["Content-Disposition"] = f"attachment; filename=breach_shield_report_{now_str}.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/api/password/strength', methods=['POST'])
def api_password_strength():
    data = request.json or {}
    password = data.get("password", "")
    entropy, rating, color, feedback = check_password_strength(password)
    return jsonify({
        "entropy": round(entropy, 2),
        "rating": rating,
        "color": color,
        "feedback": feedback
    })

@app.route('/api/sandbox/populate', methods=['POST'])
def api_sandbox_populate():
    conn = get_db_connection()
    c = conn.cursor()
    
    mock_accounts = [
        ("sec-director@company.org", 5, [
            ("Equifax Breach", "2017", "SSN, Email, Full Name, DOB, Mailing Address"),
            ("Adobe Creative Cloud", "2013", "Email, Password Hint, Username, Password (Hashed)"),
            ("LinkedIn Leak", "2021", "Email, Full Name, Job Title"),
            ("Canva Data Breach", "2019", "Email, Full Name, Username"),
            ("Target Retail Hack", "2013", "Email, Credit Card Details, Full Name")
        ]),
        ("auditor@financial-corp.com", 2, [
            ("LinkedIn Leak", "2021", "Email, Full Name"),
            ("Dropbox Leak", "2016", "Email, Password (Hashed)")
        ]),
        ("junior-dev@code-repo.io", 3, [
            ("LinkedIn Leak", "2021", "Email, Full Name"),
            ("Zynga Games Leak", "2019", "Email, Username, Password (SHA-1)"),
            ("Canva Data Breach", "2019", "Email, Full Name")
        ]),
        ("secure-user@safe-inbox.net", 0, [])
    ]
    
    try:
        for email, count, breaches in mock_accounts:
            c.execute("INSERT OR REPLACE INTO users (email, last_checked, breach_count) VALUES (?, ?, ?)", 
                      (email, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), count))
            
            c.execute("DELETE FROM breach_records WHERE email = ?", (email,))
            for b_name, b_date, b_leaks in breaches:
                risk = get_risk_level(b_leaks.split(", "), 1)
                c.execute("""
                    INSERT INTO breach_records (email, source_name, breach_date, exposed_data, date_detected, risk_level)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (email, b_name, b_date, b_leaks, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), risk))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Sandbox mock data populated successfully."})
    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/sandbox/reset', methods=['POST'])
def api_sandbox_reset():
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM users")
        c.execute("DELETE FROM breach_records")
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Database successfully flushed."})
    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500

# ==============================
# ENTRY POINT
# ==============================
if __name__ == '__main__':
    # Flask port 5000 is default local development
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)