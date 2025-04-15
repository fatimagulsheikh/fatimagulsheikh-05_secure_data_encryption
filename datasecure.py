# Develop a Streamlit-based secure data storage and retrieval system

import streamlit as st
import hashlib 
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === data information of user ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# === session state ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
    
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
    
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === load and save data ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# === encryption key generation ===
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# === UI ===
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# === Home ===
if choice == "Home":
    st.subheader("Welcome To My Data Encryption System Using Streamlit!")
    st.markdown("""
        This system allows users to:
        - 🔒 Store data with a passkey.
        - 🔓 Decrypt data with the same passkey.
        - 🚫 Lockout after 3 failed attempts.
        - 💾 No external databases are used — fully local and secure.
    """)

# === Register ===
elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")
    
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ Registered Successfully!")
        else:
            st.error("❗Both fields are required.")

# === Login ===
elif choice == "Login":
    st.subheader("🔐 User Login")
    
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"🚫 Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🚫 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# === Store Data ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first.")
    else:
        st.subheader("💾 Store Encrypted Data")
        data_to_store = st.text_input("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt And Save"):
            if data_to_store and passkey:
                encrypted = encrypt_text(data_to_store, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("❗All fields are required.")

# === Retrieve Data ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first.")
    else:
        st.subheader("📂 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found!")
        else:
            for i, item in enumerate(user_data):
                st.write(f"Encrypted Entry {i+1}:")
                st.code(item, language="text")
                
                with st.expander("🔓 Decrypt this entry"):
                    encrypted_input = st.text_area(f"Paste Encrypted Text (Entry {i+1})", value=item)
                    passkey = st.text_input(f"Enter Passkey to Decrypt Entry {i+1}", type="password", key=f"decrypt_key_{i}")
                    
                    if st.button(f"Decrypt Entry {i+1}"):
                        result = decrypt_text(encrypted_input, passkey)
                        if result:
                            st.success(f"🔓 Decrypted: {result}")
                        else:
                            st.error("❌ Incorrect passkey or corrupted data.")
