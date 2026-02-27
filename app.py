import streamlit as st
import requests
import hashlib
import sqlite3
import smtplib
import os
from email.message import EmailMessage

# ==============================
# DATABASE SETUP
# ==============================

conn = sqlite3.connect("users.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
    email TEXT,
    password TEXT
)
""")
conn.commit()

# ==============================
# PASSWORD BREACH CHECK (FREE API)
# ==============================

def check_password(password):
    sha1password = hashlib.sha1(password.encode()).hexdigest().upper()
    first5_char = sha1password[:5]
    tail = sha1password[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{first5_char}"
    response = requests.get(url)
    
    hashes = (line.split(':') for line in response.text.splitlines())
    
    for h, count in hashes:
        if h == tail:
            return count
    
    return 0

# ==============================
# EMAIL BREACH CHECK (DEMO MODE)
# ==============================

def check_email_breach(email):
    
    demo_breach_db = {
        "test@gmail.com": [
            {
                "Name": "LinkedIn",
                "BreachDate": "2021-06-01",
                "PwnCount": 700000000,
                "DataClasses": ["Emails", "Passwords"]
            }
        ],
        "admin@yahoo.com": [
            {
                "Name": "Dropbox",
                "BreachDate": "2020-03-15",
                "PwnCount": 68000000,
                "DataClasses": ["Emails"]
            }
        ]
    }
    
    return demo_breach_db.get(email, None)

# ==============================
# EMAIL ALERT SYSTEM
# ==============================

def send_alert(to_email, message):
    try:
        EMAIL_USER = os.getenv("EMAIL_USER")
        EMAIL_PASS = os.getenv("EMAIL_PASS")

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
        st.warning(f"Email alert failed: {e}")

# ==============================
# REMEDIATION SYSTEM
# ==============================

def remediation_tips():
    st.subheader("🔐 Recommended Security Actions")
    st.write("• Change your password immediately")
    st.write("• Enable Two-Factor Authentication (2FA)")
    st.write("• Avoid reusing passwords")
    st.write("• Use a password manager")
    st.write("• Monitor financial and social accounts")

# ==============================
# STREAMLIT UI
# ==============================

st.title("🛡️ Dark Web Breach Monitor Dashboard")

email = st.text_input("Enter your Email")
password = st.text_input("Enter your Password", type="password")

# ==============================
# CHECK BREACH BUTTON
# ==============================

if st.button("Check Breach Status"):

    if not email or not password:
        st.warning("Please enter both email and password.")

    else:
        breach_found = False
        alert_message = "⚠️ Dark Web Breach Alert Report\n\n"

        # 🔹 PASSWORD CHECK
        breach_count = check_password(password)

        if breach_count:
            breach_found = True
            st.error(f"⚠️ Password found {breach_count} times in breaches!")
            alert_message += f"🔐 Password was found {breach_count} times in known data breaches.\n\n"
        else:
            st.success("✅ Password NOT found in known breaches.")

        # 🔹 EMAIL CHECK
        email_result = check_email_breach(email)

        if email_result:
            breach_found = True
            st.error("⚠️ Email Found in Data Breaches!")

            alert_message += "📧 Email detected in the following breaches:\n"

            for breach in email_result:
                st.write("🔹 Breach Name:", breach["Name"])
                st.write("📅 Breach Date:", breach["BreachDate"])
                st.write("📊 Records Exposed:", breach["PwnCount"])
                st.write("🗂 Exposed Data:", ", ".join(breach["DataClasses"]))
                st.write("---")

                alert_message += f"""
- Breach Name: {breach['Name']}
  Date: {breach['BreachDate']}
  Records Exposed: {breach['PwnCount']}
  Data Exposed: {", ".join(breach['DataClasses'])}
"""

        else:
            st.success("✅ Email NOT found in known breaches.")

        # 🔹 IF EITHER ONE IS BREACHED → SEND ALERT
        if breach_found:
            alert_message += "\n🔐 Recommended Actions:\n"
            alert_message += "- Change passwords immediately\n"
            alert_message += "- Enable Two-Factor Authentication (2FA)\n"
            alert_message += "- Monitor financial and social accounts\n"

            send_alert(email, alert_message)
            remediation_tips()
            st.info("📩 Alert email sent successfully.")
# ==============================
# SAVE USER FOR MONITORING
# ==============================

if st.button("Save for Continuous Monitoring"):
    if email and password:
        c.execute("INSERT INTO users VALUES (?, ?)", (email, password))
        conn.commit()
        st.success("User saved for monitoring!")
    else:
        st.warning("Enter email and password first.")