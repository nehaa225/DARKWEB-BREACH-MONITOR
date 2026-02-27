import streamlit as st
import requests
import sqlite3
import smtplib
import os
from email.message import EmailMessage
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ==============================
# PAGE CONFIG
# ==============================

st.set_page_config(
    page_title="Dark Web Email Breach Monitor",
    page_icon="🛡️",
    layout="wide"
)

# Hide Streamlit branding
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
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
    email TEXT
)
""")
conn.commit()

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
        return None
    except:
        return None

# ==============================
# AI RISK ANALYSIS (GOOGLE GEMINI)
# ==============================

def ai_risk_analysis(email, breach_count):
    api_key = os.getenv("GOOGLE_API_KEY")

    if not api_key:
        return "⚠️ AI analysis unavailable (API key not configured)."

    try:
        # 1. Use the 1.5 Flash model and v1beta endpoint
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"

        prompt = f"""
        User email: {email}
        Number of breach sources: {breach_count}

        Provide:
        1. Risk Level (Low/Medium/High/Critical)
        2. Why this is dangerous
        3. Immediate steps
        4. Long-term protection advice
        """

        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }

        # 2. Make the request
        response = requests.post(url, json=payload, timeout=20)
        
        # 3. Check for errors specifically
        if response.status_code != 200:
            return f"⚠️ API Error: {response.json().get('error', {}).get('message', 'Unknown error')}"

        result = response.json()
        return result["candidates"][0]["content"]["parts"][0]["text"]

    except Exception as e:
        return f"⚠️ AI analysis error: {str(e)}"

# ==============================
# EMAIL REMEDIATION SECTION
# ==============================

def email_remediation():
    st.subheader("🔐 Immediate Actions Required")
    st.write("• Change passwords on affected platforms")
    st.write("• Enable 2-Factor Authentication (2FA)")
    st.write("• Check for suspicious login activity")
    st.write("• Beware of phishing emails")
    st.write("• Monitor financial & linked accounts")

# ==============================
# EMAIL ALERT SYSTEM
# ==============================

def send_alert(to_email, message):

    EMAIL_USER = os.getenv("EMAIL_USER")
    EMAIL_PASS = os.getenv("EMAIL_PASS")

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

email = st.text_input("Enter your Email Address")

if st.button("Check Email Breach Status"):

    if not email:
        st.warning("Please enter your email.")
    else:

        breach_sources = check_email_breach(email)

        if breach_sources:

            st.error("⚠️ Email Found in Data Breaches!")

            formatted_sources = ""

            for source in breach_sources:
                if isinstance(source, dict):
                    name = source.get("name", "Unknown Source")
                else:
                    name = str(source)

                st.write("🔹", name)
                formatted_sources += f"- {name}\n"

            breach_count = len(breach_sources)

            # AI ANALYSIS
            st.subheader("🤖 AI Risk Analysis")
            ai_result = ai_risk_analysis(email, breach_count)
            st.write(ai_result)

            # REMEDIATION SECTION
            email_remediation()

            # ALERT MESSAGE
            alert_message = f"""
⚠️ Dark Web Breach Alert Report

Email: {email}
Breach Sources Found: {breach_count}

Sources:
{formatted_sources}

AI Risk Analysis:
{ai_result}
"""

            send_alert(email, alert_message)
            st.info("📩 Alert email sent successfully.")

        else:
            st.success("✅ Email NOT found in known public breaches.")

# ==============================
# SAVE EMAIL FOR MONITORING
# ==============================

if st.button("Save Email for Monitoring"):
    if email:
        c.execute("INSERT INTO users VALUES (?)", (email,))
        conn.commit()
        st.success("Email saved for continuous monitoring!")
    else:
        st.warning("Enter email first.")