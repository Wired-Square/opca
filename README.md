# opca - 1Password Certificate Authority

A simple CA implementation in Python that stores data in 1Password.

A Python certificate authority implementation that uses pyca/cryptography (https://cryptography.io)
to generate keys and sign certificates, and then store them in 1Password.

The design contraints are
  - Limit the dependendies.
    - 1Password CLI
    - Python 3
    - Python Cryptography Library

  - Store no sensitive data on disk. Ever. 

This version of 1Password Certificate Authority represents a project with most features implemented.

Future features (not extensive):
- CA certificate and key renewal
- Implement private key passphrases
