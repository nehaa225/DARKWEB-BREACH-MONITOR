import streamlit as st
import requests
import sqlite3
import smtplib
import os
from email.message import EmailMessage
from dotenv import load_dotenv
import pandas as pd
from datetime import datetime

# ==============================
# LOAD ENV VARIABLES
# ==============================
load_dotenv()
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# ==============================
# PAGE CONFIG
# ==============================
st.set_page_config(
    page_title="Dark Web Email Breach Monitor",
    page_icon="🛡️",
    layout="wide"
)
st.markdown("""
    <style>
        footer {visibility: hidden;}
        #MainMenu {visibility: hidden;}
        header {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

# ==============================
# DATABASE SETUP
# ==============================
conn = sqlite3.connect("users.db", check_same_thread=False)
conn.row_factory = sqlite3.Row  # access columns by name safely
c = conn.cursor()

# Create table safely
c.execute("""
CREATE TABLE IF NOT EXISTS users(
    email TEXT UNIQUE
)
""")
conn.commit()

# ==============================
# SAFE DATABASE COLUMN UPDATE
# ==============================
def ensure_columns_exist():
    try:
        c.execute("ALTER TABLE users ADD COLUMN last_checked TEXT")
    except sqlite3.OperationalError:
        pass  # already exists

    try:
        c.execute("ALTER TABLE users ADD COLUMN breach_count INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # already exists

    # Fix NULL breach_count
    c.execute("UPDATE users SET breach_count = 0 WHERE breach_count IS NULL")
    conn.commit()

ensure_columns_exist()

# ==============================
# EMAIL BREACH CHECK
# ==============================
def check_email_breach(email):
    try:
        url = f"https://leakcheck.io/api/public?check={email}"
        response = requests.get(url, timeout=10)
        data = response.json()
        if data.get("success") and data.get("found") > 0:
            return data.get("sources")
        return []
    except Exception as e:
        st.warning(f"API error: {e}")
        return []

# ==============================
# AI RISK ANALYSIS
# ==============================
def generate_risk_analysis(email, breach_count, exposed_data_list):
    """
    Generate structured risk analysis for an email breach.
    Works even if exact exposed data is unknown.
    """
    # Data summary
    if not exposed_data_list:
        data_summary = "Information not provided by source"
        unknown_data = True
    else:
        data_summary = ', '.join(exposed_data_list)
        unknown_data = "Information not provided by source" in exposed_data_list

    # Risk level logic
    if breach_count == 0:
        risk_level = "Low"
    elif breach_count == 1 and not unknown_data:
        risk_level = "Medium"
    else:
        risk_level = "High" if breach_count >= 1 else "Medium"

    # Immediate steps
    immediate_steps = [
        "Change the password of this email immediately, and any accounts using the same password.",
        "Enable Two-Factor Authentication (2FA) wherever possible.",
        "Be alert for phishing emails or suspicious login attempts.",
        "Check if your email is listed in other breach databases (e.g., Have I Been Pwned)."
    ]

    # Long-term advice
    long_term_advice = [
        "Use a unique password for every account and consider a password manager.",
        "Regularly monitor emails for breaches or suspicious activity.",
        "Consider AI-based monitoring tools for sensitive data exposure.",
        "Review connected apps and revoke access for unknown or suspicious ones."
    ]

    # Construct output
    analysis = f"""
Email: {email}
Number of Breaches: {breach_count}
Exposed Data: {data_summary}

1️⃣ Risk Level: {risk_level}

2️⃣ Why this is dangerous:
- Your email appears in a data breach{', potentially exposing sensitive info' if unknown_data else ''}.
- Attackers could attempt account takeovers or phishing.
- Unknown exposure increases unpredictability of threats.

3️⃣ Immediate steps:
- {chr(10).join(immediate_steps)}

4️⃣ Long-term protection advice:
- {chr(10).join(long_term_advice)}
"""
    return analysis
        # Call API
        response = requests.post(url, json=payload, timeout=20)
        if response.status_code != 200:
            return f"⚠️ API Error: {response.json().get('error', {}).get('message', 'Unknown error')}"

        result = response.json()
        # Extract generated text
        ai_text = result.get("candidates", [{}])[0].get("output", "")
        return ai_text or "⚠️ AI returned no result."

    except Exception as e:
        return f"⚠️ AI analysis error: {str(e)}"

# ==============================
# REMEDIATION RECOMMENDATION
# ==============================
def remediation_recommendation(exposed_data_list, breach_count):
    recommendations = []

    # Base recommendations
    recommendations.append("• Change passwords on all affected platforms.")
    recommendations.append("• Enable Two-Factor Authentication (2FA) on all accounts.")
    recommendations.append("• Check for suspicious login activity.")
    
    # Data-specific recommendations
    if any(d.lower() in ["password", "hashedpassword"] for d in exposed_data_list):
        recommendations.append("• Your passwords were leaked. Consider using a password manager and updating all accounts immediately.")
    
    if any(d.lower() in ["email", "username"] for d in exposed_data_list) and breach_count > 1:
        recommendations.append("• Multiple breaches detected for your email. Be cautious with phishing attempts.")
    
    if any(d.lower() in ["ssn", "socialsecuritynumber", "dob"] for d in exposed_data_list):
        recommendations.append("• Sensitive personal information exposed. Consider credit monitoring or identity theft protection.")
    
    if any(d.lower() in ["credit card", "payment", "bank"] for d in exposed_data_list):
        recommendations.append("• Payment info exposed. Contact your bank and monitor financial transactions.")

    # Long-term recommendations
    recommendations.append("• Regularly monitor your emails for breaches.")
    recommendations.append("• Use unique passwords for each account.")
    recommendations.append("• Consider using AI-based monitoring for sensitive data.")

    return recommendations

# ==============================
# EMAIL ALERT
# ==============================
def send_alert(to_email, message):
    if not EMAIL_USER or not EMAIL_PASS:
        st.warning("⚠️ Email credentials not configured.")
        return
    try:
        msg = EmailMessage()
        msg.set_content(message)
        msg['Subject'] = "⚠️ Dark Web Breach Alert"
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        st.warning(f"Email sending failed: {e}")

# ==============================
# UI
# ==============================
st.title("🛡️ Dark Web Email Breach Monitor")
tab1, tab2, tab3 = st.tabs(["Monitor Email", "Dashboard", "API Docs"])

# --- TAB 1: Monitor Email ---
with tab1:
    email = st.text_input("Enter your Email Address")

    if st.button("Check Email Breach Status"):
        if not email:
            st.warning("Please enter your email.")
        else:
            breaches = check_email_breach(email)
            if breaches:
                st.error("⚠️ Email Found in Data Breaches!")
                formatted_sources = ""
                all_exposed_data = []

                for breach in breaches:
                    name = breach.get("name") or breach.get("title") or "Unknown Source"
                    date = breach.get("breachDate") or breach.get("date") or "Unknown Date"
                    leaks = breach.get("leaks") or breach.get("dataTypes") or []
                    if not leaks:
                        leaks = ["Information not provided by source"]
                    all_exposed_data.extend(leaks)
                    st.markdown(f"**🔹 Breach:** {name}")
                    st.markdown(f"📅 **Breach Date:** {date}")
                    st.markdown(f"🗂 **Exposed Data:** {', '.join(leaks)}")
                    st.markdown("---")
                    formatted_sources += f"- {name} ({date}) - Exposed Data: {', '.join(leaks)}\n"

                # AI Risk Analysis
                ai_result = ai_risk_analysis(email, len(breaches), all_exposed_data)
                st.subheader("🤖 AI Risk Analysis")
                st.write(ai_result)

                # Remediation Recommendations
                st.subheader("🛠 Remediation Recommendations")
                remediation_steps = remediation_recommendation(all_exposed_data, len(breaches))
                for step in remediation_steps:
                    st.write(step)

                # Send alert email
                alert_message = f"""
⚠️ Dark Web Breach Alert Report

Email: {email}
Number of Breaches Found: {len(breaches)}

Breach Details:
{formatted_sources}

AI Risk Analysis:
{ai_result}

Recommended Actions:
{chr(10).join(remediation_steps)}
"""
                send_alert(email, alert_message)
                st.info("📩 Alert email sent successfully.")
            else:
                st.success("✅ Email NOT found in known public breaches.")

    if st.button("Save Email for Monitoring"):
        if email:
            try:
                c.execute("INSERT INTO users(email) VALUES (?)", (email,))
                conn.commit()
                st.success("Email saved for continuous monitoring!")
            except sqlite3.IntegrityError:
                st.warning("Email is already being monitored.")
        else:
            st.warning("Enter email first.")

# --- TAB 2: Dashboard ---
with tab2:
    st.subheader("📊 Breach Monitoring Dashboard (Auto-Update)")
    c.execute("SELECT * FROM users")
    users = c.fetchall()

    if users:
        dashboard_data = []
        for user in users:
            email_db = user["email"]
            last_checked = user["last_checked"]
            previous_breach_count = int(user["breach_count"]) if user["breach_count"] is not None else 0

            breaches = check_email_breach(email_db) or []
            breach_count = len(breaches)
            last_checked_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            c.execute(
                "UPDATE users SET last_checked = ?, breach_count = ? WHERE email = ?",
                (last_checked_now, breach_count, email_db)
            )
            conn.commit()

            if breach_count > previous_breach_count:
                alert_message = f"""
⚠️ Dark Web Breach Alert Report

Email: {email_db}
Previous Breach Count: {previous_breach_count}
Current Breach Count: {breach_count}

Check the dashboard for detailed information.
"""
                send_alert(email_db, alert_message)

            dashboard_data.append({
                "Email": email_db,
                "Breach Count": breach_count,
                "Last Checked": last_checked_now
            })

        df = pd.DataFrame(dashboard_data)
        st.dataframe(df)
        st.bar_chart(df.set_index("Email")["Breach Count"])
    else:
        st.info("No emails saved for monitoring yet.")

# --- TAB 3: API Docs ---
with tab3:
    st.subheader("📖 API Integration Documentation")
    st.markdown("### 1. LeakCheck API")
    st.markdown("""
- **Purpose:** Detect if email is in known breaches  
- **Endpoint:** `https://leakcheck.io/api/public?check=<EMAIL>`  
- **Method:** GET  
- **Response:** JSON with `success`, `found`, `sources`  
""")
    st.markdown("### 2. Google Gemini AI API")
    st.markdown("""
- **Purpose:** AI-generated risk analysis  
- **Endpoint:** `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=<API_KEY>`  
- **Method:** POST  
- **Payload:** JSON with `contents`  
""")
    st.markdown("### 3. SMTP Email Alerts")
    st.markdown("""
- **Purpose:** Notify users via email  
- **Library:** `smtplib` + `email.message.EmailMessage`  
- **Requirements:** `EMAIL_USER`, `EMAIL_PASS` environment variables  
""")