import os
import hashlib
import streamlit as st
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Generate RSA key pair
private_key = generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

def hash_file(file):
    """Compute SHA-256 hash of the uploaded file"""
    sha256 = hashlib.sha256()
    for chunk in iter(lambda: file.read(4096), b""):
        sha256.update(chunk)
    return sha256.digest()  # 32-byte output

def sign_message(private_key, message):
    """Sign a hash with the private key"""
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_signature(public_key, signature, message):
    """Verify a digital signature"""
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Streamlit UI
st.title("Digital Signature Scheme (DSS)")

st.write("Upload a file to generate a digital signature.")

uploaded_file = st.file_uploader("Choose a file", type=["txt", "pdf", "xlsx", "csv", "png", "jpg"])

if uploaded_file:
    st.write(f"**Uploaded File:** {uploaded_file.name}")

    # Compute hash
    uploaded_file.seek(0)  # Reset file pointer
    file_hash = hash_file(uploaded_file)

    # Sign the hash
    signature = sign_message(private_key, file_hash)

    # Verify the signature
    verification_result = verify_signature(public_key, signature, file_hash)

    # Display results
    st.subheader("Results")
    st.write(f"**File Hash (SHA-256 Digest):** {file_hash.hex()}")
    st.write(f"**Signature:** {signature.hex()}")
    st.write(f"**Verification Status:** {'✅ Verified' if verification_result else '❌ Not Verified'}")

    # Download Signature
    st.download_button(
        label="Download Signature",
        data=signature,
        file_name="signature.bin",
        mime="application/octet-stream"
    )
