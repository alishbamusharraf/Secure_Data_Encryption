import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

DATA_FILE = "data.json"

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "last_failed_time" not in st.session_state:
    st.session_state.last_failed_time = 0

def hash_passkey(passkey, salt):
    key = pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return key.hex()

def generate_key(passkey, salt):
    kdf = pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000, dklen=32)
    return urlsafe_b64encode(kdf)

def encrypt_data(text, passkey, username):
    key = generate_key(passkey, username)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, username):
    hashed_passkey = hash_passkey(passkey, username)

    for user, entries in stored_data.items():
        for entry in entries:
            if entry["encrypted_text"] == encrypted_text and entry["passkey"] == hashed_passkey:
                try:
                    key = generate_key(passkey, username)
                    cipher = Fernet(key)
                    st.session_state.failed_attempts = 0
                    return cipher.decrypt(encrypted_text.encode()).decode()
                except:
                    pass

    st.session_state.failed_attempts += 1
    st.session_state.last_failed_time = time.time()
    return None

st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    username = st.text_input("Enter Username:")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if username and user_data and passkey:
            hashed_passkey = hash_passkey(passkey, username)
            encrypted_text = encrypt_data(user_data, passkey, username)

            if username not in stored_data:
                stored_data[username] = []
            stored_data[username].append({"encrypted_text": encrypted_text, "passkey": hashed_passkey})
            save_data(stored_data)

            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔑 Retrieve Data Securely")

    if st.session_state.failed_attempts >= 3:
        time_diff = time.time() - st.session_state.last_failed_time
        if time_diff < 60:
            st.warning(f"🔒 Too many failed attempts! Please wait {int(60 - time_diff)} seconds.")
            st.stop()
        else:
            st.session_state.failed_attempts = 0

    username = st.text_input("Enter Username:")
    encrypted_text = st.text_input("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if username and encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey, username)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect credentials! Attempts remaining: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
