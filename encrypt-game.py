#!/usr/bin/env python3
"""
Encrypt the <script> content of a game HTML file using AES-256-GCM.
The encrypted file replaces the game code with a decryption loader
that waits for the password via postMessage from the parent frame.

Usage: python3 encrypt-game.py <game-file.html> <password>
"""

import sys
import os
import re
import base64
import hashlib

# Use PyCryptodome if available, otherwise fall back to openssl
try:
    from Crypto.Cipher import AES
    HAS_PYCRYPTO = True
except ImportError:
    HAS_PYCRYPTO = False

def encrypt_aes_gcm(plaintext_bytes, password, salt, iv):
    """Encrypt using AES-256-GCM with PBKDF2 key derivation."""
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
    if HAS_PYCRYPTO:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        return ciphertext, tag
    else:
        # Pure Python AES-GCM via openssl subprocess
        import subprocess
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as pf:
            pf.write(plaintext_bytes)
            plainfile = pf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as ef:
            encfile = ef.name
        try:
            result = subprocess.run([
                'openssl', 'enc', '-aes-256-gcm',
                '-in', plainfile, '-out', encfile,
                '-K', key.hex(),
                '-iv', iv.hex(),
                '-nosalt'
            ], capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(f"openssl failed: {result.stderr.decode()}")
            with open(encfile, 'rb') as f:
                data = f.read()
            # openssl appends 16-byte tag
            ciphertext = data[:-16]
            tag = data[-16:]
            return ciphertext, tag
        finally:
            os.unlink(plainfile)
            os.unlink(encfile)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <game-file.html> <password>")
        sys.exit(1)

    filepath = sys.argv[1]
    password = sys.argv[2]

    with open(filepath, 'r', encoding='utf-8') as f:
        html = f.read()

    # Extract script content
    match = re.search(r'<script>(.*?)</script>', html, re.DOTALL)
    if not match:
        print("ERROR: No <script> tag found in file")
        sys.exit(1)

    script_content = match.group(1)

    # Generate random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(12)

    # Encrypt
    plaintext_bytes = script_content.encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

    # Use Python's cryptography if available, otherwise pure implementation
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        ct_with_tag = aesgcm.encrypt(iv, plaintext_bytes, None)
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
    except ImportError:
        # Fallback: use openssl CLI
        import subprocess, tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.plain') as pf:
            pf.write(plaintext_bytes)
            plainfile = pf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as ef:
            encfile = ef.name
        try:
            cmd = [
                'openssl', 'enc', '-aes-256-gcm',
                '-in', plainfile, '-out', encfile,
                '-K', key.hex(), '-iv', iv.hex()
            ]
            result = subprocess.run(cmd, capture_output=True)
            # openssl enc doesn't support GCM well, use python instead
            raise ImportError("openssl GCM not reliable, using fallback")
        except Exception:
            os.unlink(plainfile)
            os.unlink(encfile)
            # Last resort: implement CTR + GMAC manually? No.
            # Actually, let's just require the cryptography package
            print("Installing 'cryptography' package...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'cryptography', '-q'])
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            ct_with_tag = aesgcm.encrypt(iv, plaintext_bytes, None)
            ciphertext = ct_with_tag[:-16]
            tag = ct_with_tag[-16:]

    # Pack: salt(16) + iv(12) + ciphertext + tag(16)
    packed = salt + iv + ciphertext + tag
    encrypted_b64 = base64.b64encode(packed).decode('ascii')

    # Build the decryption loader script
    loader = f'''
const _E="{encrypted_b64}";
const _I=100000;
async function _decrypt(pw){{
  const raw=Uint8Array.from(atob(_E),c=>c.charCodeAt(0));
  const salt=raw.slice(0,16),iv=raw.slice(16,28);
  const payload=raw.slice(28);
  const enc=new TextEncoder();
  const km=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey(
    {{name:'PBKDF2',salt,iterations:_I,hash:'SHA-256'}},
    km,{{name:'AES-GCM',length:256}},false,['decrypt']
  );
  const plain=await crypto.subtle.decrypt({{name:'AES-GCM',iv}},key,payload);
  return new TextDecoder().decode(plain);
}}
window.addEventListener('message',async e=>{{
  if(e.data&&e.data.type==='key'){{
    try{{
      const code=await _decrypt(e.data.key);
      eval(code);
    }}catch(err){{
      console.error('Decrypt failed:',err);
    }}
  }}
}});
if(window!==window.parent)parent.postMessage({{type:'ready'}},'*');
'''

    # Replace script content
    new_html = html[:match.start(1)] + loader + html[match.end(1):]

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_html)

    script_kb = len(plaintext_bytes) / 1024
    enc_kb = len(encrypted_b64) / 1024
    print(f"Encrypted {filepath}: {script_kb:.1f}KB script -> {enc_kb:.1f}KB ciphertext")

if __name__ == '__main__':
    main()
