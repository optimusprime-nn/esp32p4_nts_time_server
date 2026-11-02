# AES-SIV unit tests

Unity tests for `main/nts_aes_siv.c` (the AEAD used by NTS cookies and NTS-protected NTP). The test cases are in `test/test_nts_aes_siv.c`.

## What's covered

- The firmware's own known-answer self-test, `nts_aes_siv_self_test()`. It runs RFC 5297 A.1 plus NTS-shaped vectors, round trips, and tag-tamper rejection.
- A round trip at NTS cookie size (124-byte plaintext).
- Rejection of tampered associated data, nonce or ciphertext. A failed open must leave no plaintext behind.
- Output-size and argument checks.
- An empty plaintext, which is the shape of an NTS client request.

## Run

This is a separate app with its own partition table and default config. **Use a spare or development board.** Don't flash it to a deployed time server: the board would run the test app until the firmware is flashed back, so it would serve no time meanwhile.

```bash
cd test/nts_aes_siv_test_app
idf.py set-target esp32p4
idf.py -p <PORT> flash monitor
```

The console ends with Unity's summary, for example `5 Tests 0 Failures 0 Ignored`.
