# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pycryptodome>=3.20.0",
# ]
# ///
from Crypto.Hash import MD4
import base64
import sys

if sys.stdin.isatty():
    base64_input = input("Base64: ").strip()
else:
    base64_input = sys.stdin.read().strip()

decoded = base64.b64decode(base64_input)
nt_hash = MD4.new(decoded).hexdigest()

print(f"\nNT Hash: {nt_hash}"
