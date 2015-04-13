### This project describes a private data communication protocol. ###

This project contains code that can be used to securely transmit 64 bit values. The code here is an implementation of the code required to receive values.

Features of the encryption scheme:
  * Small ciphertext. 8 byte plaintext is expanded to 28 bytes ciphertext.
  * Integrity. HMAC used to authenticate message.
  * Monotonic initialization vector. It is possible to ensure the 16 byte initialization vector never repeats.
  * Time based. The current time is used as a component of the initialization vector so it is possible to recognize significantly stale messages.