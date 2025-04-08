import streamlit as st
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# In-memory storage for users and keys
USERS = {}

# === Utility Functions ===

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def hash_file(file):
    sha256 = hashlib.sha256()
    for chunk in iter(lambda: file.read(4096), b""):
        sha256.update(chunk)
    return sha256.digest()

def sign_message(private_key, message):
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_signature(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# === Streamlit App ===

st.title("🔐 Digital Signature Scheme with User Accounts")

st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Register User", "Sign File", "Verify Signature"])

# === Register Page ===
if page == "Register User":
    st.header("👤 Register a New User")
    username = st.text_input("Choose a username")

    if st.button("Register"):
        if username in USERS:
            st.warning("Username already exists.")
        elif username.strip() == "":
            st.error("Username cannot be empty.")
        else:
            private_key, public_key = generate_key_pair()
            USERS[username] = {"private_key": private_key, "public_key": public_key}
            st.success(f"User '{username}' registered successfully!")
            st.code(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(), language="bash")

# === Sign File Page ===
elif page == "Sign File":
    st.header("✍️ Sign a File")
    if USERS:
        signer = st.selectbox("Select a registered user", list(USERS.keys()))
        uploaded_file = st.file_uploader("Upload file to sign")

        if uploaded_file and signer:
            uploaded_file.seek(0)
            file_hash = hash_file(uploaded_file)
            private_key = USERS[signer]["private_key"]
            signature = sign_message(private_key, file_hash)

            st.subheader("✅ Signature Created")
            st.write(f"**File Hash (SHA-256):** {file_hash.hex()}")
            st.write(f"**Signature:** {signature.hex()}")

            st.download_button(
                "Download Signature",
                data=signature,
                file_name="signature.bin",
                mime="application/octet-stream"
            )
    else:
        st.warning("No users registered. Go to 'Register User' first.")

# === Verify Signature Page ===
elif page == "Verify Signature":
    st.header("🔎 Verify File Signature")

    if USERS:
        verifier = st.selectbox("Select a user (public key will be used)", list(USERS.keys()))
        uploaded_file = st.file_uploader("Upload the original file")
        uploaded_sig = st.file_uploader("Upload the signature", type=["bin"])

        if uploaded_file and uploaded_sig:
            uploaded_file.seek(0)
            file_hash = hash_file(uploaded_file)
            signature = uploaded_sig.read()
            public_key = USERS[verifier]["public_key"]
            result = verify_signature(public_key, signature, file_hash)

            if result:
                st.success("✅ Signature Verified")
            else:
                st.error("❌ Signature Verification Failed")
    else:
        st.warning("No users registered. Go to 'Register User' first.")
