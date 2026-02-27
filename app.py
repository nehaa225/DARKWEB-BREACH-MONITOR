import streamlit as st
import requests
import hashlib
import sqlite3
import smtplib
import time
from email.message import EmailMessage

# -----------------------------
# DATABASE SETUP
# -----------------------------
conn = sqlite3.connect("users.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
    email TEXT,
    password TEXT
)
""")
conn.commit()

# -----------------------------
# PASSWORD BREACH CHECK FUNCTION
# -----------------------------
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

# -----------------------------
# EMAIL ALERT FUNCTION
# -----------------------------
def send_alert(to_email, message):
    try:
        msg = EmailMessage()
        msg.set_content(message)
        msg['Subject'] = "⚠️ Dark Web Breach Alert"
        msg['From'] = "nehaareddy02@gmail.com" 
        msg['To'] = to_email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login("nehaareddy02@gmail.com", "djxq lemr nnrr ludx") 
        server.send_message(msg)
        server.quit()

        return True
    except:
        return False

# -----------------------------
# REMEDIATION SYSTEM
# -----------------------------
def remediation_tips():
    st.subheader("🔐 Recommended Security Actions")
    st.write("• Change your password immediately")
    st.write("• Enable Two-Factor Authentication (2FA)")
    st.write("• Avoid reusing passwords")
    st.write("• Use a trusted password manager")
    st.write("• Monitor financial and online accounts")

# -----------------------------
# STREAMLIT UI
# -----------------------------
st.set_page_config(page_title="Dark Web Breach Monitor", page_icon="🛡️")

st.title("🛡️ Dark Web Breach Monitor Dashboard")
st.write("Monitor your credentials against known data breaches.")

email = st.text_input("📧 Enter your Email")
password = st.text_input("🔑 Enter your Password", type="password")

# -----------------------------
# CHECK BREACH BUTTON
# -----------------------------
if st.button("🔍 Check Breach Now"):
    if password == "":
        st.warning("Please enter a password.")
    else:
        breach_count = check_password(password)

        if breach_count:
            st.error(f"⚠️ Password found {breach_count} times in data breaches!")
            
            # Send Email Alert
            if email != "":
                sent = send_alert(email, 
                    f"Your password was found {breach_count} times in data breaches. Please change it immediately.")
                if sent:
                    st.success("📩 Alert Email Sent Successfully!")
                else:
                    st.warning("Email alert failed. Check your Gmail configuration.")

            remediation_tips()
        else:
            st.success("✅ Password NOT found in known breaches.")

# -----------------------------
# SAVE USER BUTTON
# -----------------------------
if st.button("💾 Save Credentials for Monitoring"):
    if email == "" or password == "":
        st.warning("Please enter both email and password.")
    else:
        c.execute("INSERT INTO users VALUES (?, ?)", (email, password))
        conn.commit()
        st.success("User saved successfully!")

# -----------------------------
# SHOW STORED USERS
# -----------------------------
if st.checkbox("📂 Show Stored Users"):
    c.execute("SELECT * FROM users")
    data = c.fetchall()
    for row in data:
        st.write("📧", row[0])

# -----------------------------
# CONTINUOUS MONITORING (DEMO)
# -----------------------------
if st.button("🚀 Start Continuous Monitoring (Demo Mode)"):
    st.info("Monitoring started... (Checks every 60 seconds)")

    while True:
        c.execute("SELECT * FROM users")
        users = c.fetchall()

        for user in users:
            stored_email = user[0]
            stored_password = user[1]

            breach_count = check_password(stored_password)

            if breach_count:
                send_alert(stored_email, 
                    f"New breach detected! Your password was found {breach_count} times. Change immediately!")

        time.sleep(60)