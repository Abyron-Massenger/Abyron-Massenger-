# ABYRON Security Gate

Before calling ABYRON production-secure, all of these must be implemented and reviewed:

- authenticated device identity
- authenticated key exchange
- forward secrecy / ratcheting
- key-change warnings
- group sender-key rotation
- secure multi-device provisioning
- replay protection
- message ordering strategy
- attachment encryption
- encrypted local database
- secure Android key storage
- push notification privacy
- strict Supabase RLS
- abuse/rate-limit controls
- secure scheduled-message worker
- dependency pinning and updates
- independent security audit

The included Web Crypto ECDH/AES layer is a development foundation, not a finished production protocol.
