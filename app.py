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
    email TEXT UNIQUE
)
""")
conn.commit()

# ==============================
# EMAIL BREACH CHECK
# ==============================
def check_email_breach(email):
    """Returns list of breaches with detailed info"""
    try:
        url = f"https://leakcheck.io/api/public?check={email}"
        response = requests.get(url, timeout=10)
        data = response.json()
        if data.get("success") and data.get("found") > 0:
            return data.get("sources")
        return None
    except Exception as e:
        st.warning(f"API error: {e}")
        return None

# ==============================
# AI RISK ANALYSIS (Google Gemini)
# ==============================
def ai_risk_analysis(email, breach_count, exposed_data_list):
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return "⚠️ AI analysis unavailable (API key not configured)."

    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"

        # Handle missing data types
        if "Information not provided by source" in exposed_data_list:
            data_summary = ', '.join([d for d in exposed_data_list if d != "Information not provided by source"])
            note = "⚠️ Some exposed data types were not provided by the source; treat this as higher risk."
            if not data_summary:
                data_summary = "Information not provided by source"
        else:
            data_summary = ', '.join(exposed_data_list)
            note = ""

        prompt = f"""
User email: {email}
Number of breaches: {breach_count}
Exposed data types: {data_summary}

{note}

Provide:
1. Risk Level (Low/Medium/High/Critical)
2. Why this is dangerous
3. Immediate steps
4. Long-term protection advice
"""

        payload = {"contents": [{"parts": [{"text": prompt}]}]}

        response = requests.post(url, json=payload, timeout=20)
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
    st.subheader("🔐 Recommended Immediate Actions")
    st.write("• Change passwords on affected platforms")
    st.write("• Enable Two-Factor Authentication (2FA) everywhere")
    st.write("• Check for suspicious login activity")
    st.write("• Beware of phishing emails")
    st.write("• Monitor financial & linked accounts")
    st.write("---")

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

# --- CHECK BREACH STATUS ---
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
                # Handle missing or inconsistent fields
                name = breach.get("name") or breach.get("title") or "Unknown Source"
                date = breach.get("breachDate") or breach.get("date") or "Unknown Date"
                leaks = breach.get("leaks") or breach.get("dataTypes") or []

                # Updated placeholder for unknown data types
                if not leaks:
                    leaks = ["Information not provided by source"]

                all_exposed_data.extend(leaks)

                # Display detailed breach info
                st.markdown(f"**🔹 Breach:** {name}")
                st.markdown(f"📅 **Breach Date:** {date}")
                st.markdown(f"🗂 **Exposed Data:** {', '.join(leaks)}")
                st.markdown("---")

                formatted_sources += f"- {name} ({date}) - Exposed Data: {', '.join(leaks)}\n"

            # AI Risk Analysis
            ai_result = ai_risk_analysis(email, len(breaches), all_exposed_data)
            st.subheader("🤖 AI Risk Analysis")
            st.write(ai_result)

            # Immediate remediation tips
            email_remediation()

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
- Change passwords on affected platforms
- Enable 2FA everywhere
- Check for suspicious login activity
- Monitor financial & linked accounts

⚠️ Note: Some breach data may be incomplete; review each source manually.
"""
            send_alert(email, alert_message)
            st.info("📩 Alert email sent successfully.")

        else:
            st.success("✅ Email NOT found in known public breaches.")

# --- SAVE EMAIL FOR CONTINUOUS MONITORING ---
if st.button("Save Email for Monitoring"):
    if email:
        try:
            c.execute("INSERT INTO users VALUES (?)", (email,))
            conn.commit()
            st.success("Email saved for continuous monitoring!")
        except sqlite3.IntegrityError:
            st.warning("Email is already being monitored.")
    else:
        st.warning("Enter email first.")