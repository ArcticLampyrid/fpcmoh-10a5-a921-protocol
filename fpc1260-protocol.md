# FPC1260 (`10a5:a921`) USB/TLS protocol notes

Notes for the demo capture path against the `10a5:a921` (FPC1260) sensor — what
`fpc1260-capture-loop.py` actually uses. Not a vendor spec. All offsets and
sizes come from one tested unit (`sensor=0x04ec`, `hw_id=0x0331`, raw image
`64x176`, firmware `024.26.0.39`).

## Transport

- USB VID:PID `10a5:a921`, interface `0`, bulk IN endpoint `0x81` (9800: `0x82`).
- A USB device **reset** is issued on open before any command.
- Host → device: vendor control transfers
  - `bmRequestType = 0x40` (OUT) or `0xc0` (IN)
  - `bRequest = command id`
  - `wValue = command-specific selector`
  - `wIndex = 0`
- Device → host async messages and TLS records: bulk IN on `0x81`.

Bulk header fields are **little-endian** (9800: big-endian). Small
control-transfer payloads (session id) are raw 4-byte blobs.

## Bulk event framing

Every bulk message starts with a 12-byte little-endian header:

| offset | field     | size           |
| ------ | --------- | -------------- |
| 0      | event_id  | 4              |
| 4      | total_len | 4              |
| 8      | status    | 4              |
| 12     | body      | total_len − 12 |

`total_len` is the **full** event length including the header. The same header
is reused inside the TLS plaintext stream.

### Events used by the demo

| id     | name          | notes                                |
| ------ | ------------- | ------------------------------------ |
| `0x02` | `INIT_RESULT` | Plain event after `INIT` (50 bytes). |
| `0x05` | `TLS_RECORD`  | Encrypted TLS bytes from device.     |
| `0x06` | `FINGER_DOWN` | Finger present.                      |
| `0x07` | `FINGER_UP`   | Finger removed.                      |
| `0x08` | `IMG`         | Plaintext image event inside TLS.    |

### `INIT_RESULT` body

```c
struct fpc_init_result {    // event 0x02, 50 bytes
    le32 event_id;          // 0x02
    le32 total_len;         // 50
    le32 status;            // 0 on success
    le16 sensor;            // observed 0x04ec
    le16 hw_id;             // observed 0x0331
    le16 width;             // observed 64
    le16 height;            // observed 176
    char fw_version[16];    // observed "024.26.0.39"
    le16 fw_caps;           // observed 0x0002
    u8   reserved[12];
};
```

The demo reads sensor id, hardware id, raw dimensions, firmware version, and
firmware caps from `INIT_RESULT`; no separate state control request is needed.

## Command table

| cmd    | name               | dir | value         | payload                   |
| ------ | ------------------ | --- | ------------- | ------------------------- |
| `0x01` | `INIT`             | OUT | `0x01`        | 4-byte session id         |
| `0x02` | `ARM`              | OUT | `0x01`        | 4-byte session id         |
| `0x03` | `ABORT`            | OUT | `0x01`        | none                      |
| `0x05` | `TLS_INIT`         | OUT | `0x01`        | none                      |
| `0x06` | `TLS_DATA`         | OUT | `0x01`        | TLS bytes, ≤ 56 per call  |
| `0x08` | `INDICATE_S_STATE` | OUT | `0x10`/`0x11` | none (S0 wake / SX sleep) |
| `0x09` | `GET_IMG`          | OUT | `0x00`        | none                      |
| `0x0d` | `SET_TLS_KEY`      | OUT | `0x00`        | 119-byte sealed key blob  |
| `0x11` | `CLR_IMG`          | OUT | `0x00`        | none                      |

## Capture sequence

```text
# Open + key
OUT 0x01 v=0x01  payload=session_id        # INIT (random 4-byte session id)
BULK IN          event 0x02 INIT_RESULT    # sensor/hw/fw/dims
OUT 0x08 v=0x10                            # S0 wake
OUT 0x11 v=0x00                            # CLR_IMG, clear stale image
OUT 0x0d v=0x00  payload=sealed_key_blob   # SET_TLS_KEY (119 bytes)
# Let the device process the key before starting TLS handshake (MUST)
DELAY 0.1s
# TLS up (host is the TLS client)
OUT 0x05 v=0x01                            # start handshake
                                           # do_handshake loop:
OUT 0x06 v=0x01  payload=TLS bytes         #   ≤56 bytes per call
BULK IN          event 0x05 (TLS bytes from device)
                                           #   ... repeat until handshake done

# Per image (loop)
OUT 0x02 v=0x01  payload=session_id        # ARM, enter wait-for-finger
BULK IN          event 0x06 FINGER_DOWN    # (0x07 FINGER_UP / 0x05 keepalive ignored)
OUT 0x09 v=0x00
BULK IN          event 0x05 (TLS records)
                 → TLS plaintext event 0x08 (image)
OUT 0x11 v=0x00                            # CLR_IMG

# Close
OUT 0x03 v=0x01                            # ABORT
OUT 0x08 v=0x11                            # SX sleep
```

## TLS

- TLS 1.2, **host is the client, device is the server**.
- Cipher list offered (best first):
  `PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:PSK-AES128-CBC-SHA256`
- PSK identity (host → device): `"Disum PSK"`.
- The host generates a fresh 32-byte PSK each session, wraps it into a 119-byte
  `SET_TLS_KEY` blob, and uses the same PSK in the TLS client callback. 9800
  instead reads and unwraps a sealed PSK blob from the device.
- On modern OpenSSL the cipher string must include `@SECLEVEL=0` to allow
  plain PSK.
- Host → device TLS bytes must be fragmented to **≤ 56 bytes per `TLS_DATA`**
  control transfer (9800: ≤ 64).
- Device → host TLS bytes arrive as bulk event `0x05`; feed the body
  (everything after the 12-byte event header) straight into the TLS engine.

Inside the TLS plaintext stream the same 12-byte little-endian event header is
reused. After `GET_IMG`, expect event `0x08` (image).

## Sealed key blob (pushed via `SET_TLS_KEY`)

The host pushes a generated 119-byte blob.

### Blob layout

28-byte little-endian header followed by the payload:

```c
struct fpc_sealed_blob {
    le32 magic;    // 0x0dec0ded
    le32 ct_off;   // 28
    le32 ct_len;   // 32, plaintext key length, not encrypted byte count
    le32 aad_off;  // 76
    le32 aad_len;  // 11
    le32 tag_off;  // 87
    le32 tag_len;  // 32
    u8   data[];
};
```

For the TLS key blob:

```text
packet[28:76]   encrypted_key, 48 bytes = AES-CBC(psk || 16-byte pad)
packet[76:87]   aad, ASCII "FPC_KEY_AAD", 11 bytes
packet[87:119]  tag, 32 bytes
```

### Key derivation

The sealing keys and IV are derived from constant labels (source:
`win-driver/fpc_enclave.dll`, Huawei application-key derivation):

```text
local_key = SHA256("FPC_SEALING_KEY\0")
hmac_key  = HMAC-SHA256(local_key, BE32(1) || "application keys\0" || BE32(512))
crypt_key = HMAC-SHA256(local_key, BE32(2) || "application keys\0" || BE32(512))
iv        = HMAC-SHA256(hmac_key, "iv\0" || BE32(0x2020f00d))[0:16]
```

Concrete values:

```text
local_key =
895e04cb72d101ac98fd2589f656a64dc929d4219f97fd58aa645a1f71ad5c6d

hmac_key =
55c1ea29224bebfd770491b10b681d4fd5141f320feccf79e0f4aecc7ba113f8

crypt_key =
c79e765c8b53b301408ce9a0f99084b393c9fc84e8339032c5a6c9732b6663fe

iv =
7cf6431fd8ea04e0f3a1f4df043fbffb
```

### Encode flow

Inputs:

```text
psk: 32 bytes
pad: 16 bytes, random for new keys
aad: "FPC_KEY_AAD"
```

Flow:

```text
encrypted_key  = AES-256-CBC-Encrypt(crypt_key, iv, psk)
tag            = HMAC-SHA256(hmac_key, "FPC_HMAC_KEY\0" || encrypted_key || aad)
packet = header || encrypted_key || pad || aad || tag
```

Reference Python:

```python
local_key = sha256(b"FPC_SEALING_KEY\0")
hmac_key = hmac_sha256(local_key, b"\x00\x00\x00\x01" + b"application keys\0" + b"\x00\x00\x02\x00")
crypt_key = hmac_sha256(local_key, b"\x00\x00\x00\x02" + b"application keys\0" + b"\x00\x00\x02\x00")
iv = hmac_sha256(hmac_key, b"iv\0" + b"\x20\x20\xf0\x0d")[:16]
encrypted_key = aes_256_cbc_encrypt(crypt_key, iv, psk)
tag = hmac_sha256(hmac_key, b"FPC_HMAC_KEY\0" + encrypted_key + aad)
```

### Decode flow

To decode or verify a packet:

1. Parse the first 28 bytes as `<7I`.
2. Require `magic == 0x0dec0ded`.
3. Read `ct_len` bytes of key material length from the header. For A921 TLS key,
   this is `32`.
4. Extract `encrypted_key = packet[ct_off : ct_off + ct_len]`.
5. Extract `aad = packet[aad_off : aad_off + aad_len]`; expected `FPC_KEY_AAD`.
6. Extract `tag = packet[tag_off : tag_off + tag_len]`.
7. Derive `hmac_key`, `crypt_key`, and `iv` as above.
8. Verify `tag == HMAC-SHA256(hmac_key, "FPC_HMAC_KEY\0" || encrypted_key || aad)`.
9.  Decrypt `psk = AES-256-CBC-Decrypt(crypt_key, iv, encrypted_key)`.

## TLS plaintext image event

After `GET_IMG`, the TLS plaintext stream yields:

```c
struct fpc_tls_plain_image {
    le32 event_id;    // 0x08
    le32 total_len;   // observed 11288 (= 24 + 64*176)
    le32 status;      // 0
    u8   meta[12];    // session_id || 8 zero bytes
    u8   pixels[width * height];  // grayscale, 64*176 = 11264
};
```

Pixel window: `event[24 .. total_len)`. The 12 metadata bytes are the 4-byte
session id sent via `INIT`/`ARM` followed by 8 zero bytes; they are not needed
to render the raw fingerprint, so the demo skips them.

The raw frame is **64 × 176** (columns scanned) and should be rotated **90°
counter-clockwise** into the normalized **176 × 64** image before use.

### Image transfer packet shape

For the observed image transfer, device → host sent eleven full TLS bulk events
and one short final event:

| bulk len  | FPC header                  | TLS record                | plaintext   |
| --------- | --------------------------- | ------------------------- | ----------- |
| 1065 × 11 | `05 00 00 00 29 04 00 00 …` | app-data `17 03 03 04 18` | 1024 B each |
| 65 × 1    | `05 00 00 00 41 00 00 00 …` | app-data `17 03 03 00 30` | 24 B        |

The GCM record overhead is 24 bytes (`8` explicit nonce + `16` tag), so
`0x0418 − 24 = 1024` and `0x0030 − 24 = 24`. Total plaintext is
`11*1024 + 24 = 11288`, exactly the image event `total_len`.
