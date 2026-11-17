"""Sanity check that genuine ML-KEM-768 is available in the installed cryptography package."""
from cryptography.hazmat.primitives.asymmetric import mlkem

priv = mlkem.MLKEM768PrivateKey.generate()
secret_sender, ciphertext = priv.public_key().encapsulate()
secret_receiver = priv.decapsulate(ciphertext)
print("SUCCESS: Genuine ML-KEM-768 is working!")
print("Shared secrets match:", secret_sender == secret_receiver)
print("Encapsulation ciphertext size:", len(ciphertext), "bytes")
