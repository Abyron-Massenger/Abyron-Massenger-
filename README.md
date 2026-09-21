# ABYRON Android Nearby Transport

This module is the native transport layer that a future Android app should implement.

Interface:
- discover()
- connect(peer)
- send(packet)
- onPacket(packet)
- disconnect(peer)

Packet is ALWAYS ciphertext:
message_id, destination, ciphertext, created_at, expiry, hop_count, transport_nonce.

Recommended platform transports:
- Bluetooth LE
- Wi-Fi Direct / local Wi-Fi
- Android Nearby Connections where appropriate

Mesh rules:
1. Encrypt before entering transport.
2. Relays never decrypt.
3. Deduplicate by message_id.
4. Decrement hop_count.
5. Expire old packets.
6. Do not expose unnecessary user metadata.
7. Sync ciphertext to server when Internet becomes available.

OS support and background execution rules vary by Android version/device, so this cannot be guaranteed as a browser feature.