#!/usr/bin/env python3
"""Capture raw fingerprint images from a 10a5:a921 (FPC1260) sensor.

Demo of the open USB + TLS-PSK acquisition path. Press Ctrl+C to stop.

See fpc1260-protocol.md for the wire protocol.

Requires Python 3.13+ (for ssl.SSLContext.set_psk_client_callback).
Runtime deps: pyusb, cryptography, Pillow (only for PNG output).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import signal
import ssl
import struct
from dataclasses import dataclass
from pathlib import Path
import time

import usb.core
import usb.util
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from PIL import Image
except ImportError:
    Image = None


# --- USB ---------------------------------------------------------------------
VID, PID = 0x10A5, 0xA921
IFACE = 0
EP_IN = 0x81
EP_IN_MAX = 4096
CTRL_TIMEOUT_MS = 5000
BULK_TIMEOUT_MS = 30000
TLS_FRAGMENT_MAX = 56  # host -> device TLS bytes per control OUT 0x06

# Vendor commands (control OUT unless noted).
CMD_INIT = 0x01  # v=0x01, payload=session_id (4 bytes)
CMD_ARM = 0x02  # v=0x01, payload=session_id (4 bytes)
CMD_ABORT = 0x03  # v=0x01
CMD_TLS_INIT = 0x05  # v=0x01
CMD_TLS_DATA = 0x06  # v=0x01, payload=TLS bytes (<=56)
CMD_INDICATE_S_STATE = 0x08  # v=0x10 (S0 wake) or v=0x11 (SX sleep)
CMD_GET_IMG = 0x09  # v=0x00
CMD_SET_TLS_KEY = 0x0D  # v=0x00, payload=119-byte sealed key blob
CMD_CLR_IMG = 0x11  # v=0x00

# Bulk event ids (12-byte little-endian header: event_id, total_len, status).
EVT_INIT_RESULT = 0x02
EVT_TLS_RECORD = 0x05
EVT_FINGER_DOWN = 0x06
EVT_FINGER_UP = 0x07
EVT_IMG = 0x08
FPC_HEADER_SIZE = 12
IMAGE_HEADER_SIZE = 24  # 12-byte event header + 12 metadata bytes

# --- TLS / key material ------------------------------------------------------
TLS_PSK_IDENTITY = "Disum PSK"
# The host generates a fresh 32-byte PSK each session and seals it into the
# 119-byte SET_TLS_KEY blob (LE 0x0dec0ded header); see make_tls_key_blob and
# fpc1260-protocol.md for the key/IV derivation.
SEAL_MAGIC = 0x0DEC0DED
SEAL_AAD = b"FPC_KEY_AAD"
SEAL_KEY = hashlib.sha256(b"FPC_SEALING_KEY\0").digest()
TLS_KEY_SIZE = 32
TLS_KEY_PAD_SIZE = 16
# Cipher list the driver offers (GCM first); @SECLEVEL=0 enables plain PSK.
TLS_CIPHERS = (
    "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:PSK-AES128-CBC-SHA256:@SECLEVEL=0"
)


stop = False


def handle_sigint(*_):
    global stop
    if not stop:
        print("\nstopping...", flush=True)
    stop = True


@dataclass
class InitInfo:
    sensor: int
    hw_id: int
    raw_width: int
    raw_height: int
    firmware: str
    fw_caps: int


@dataclass
class Event:
    event_id: int
    total_len: int
    status: int
    data: bytes


# --- USB helpers -------------------------------------------------------------


def open_device():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        raise SystemExit(f"device {VID:04x}:{PID:04x} not found")
    for op in (
        lambda: dev.set_auto_detach_kernel_driver(True),
        lambda: dev.reset(),
        lambda: dev.set_configuration(),
    ):
        try:
            op()
        except (AttributeError, NotImplementedError, usb.core.USBError):
            pass
    usb.util.claim_interface(dev, IFACE)
    return dev


def ctrl_out(dev, request, value, payload=b""):
    sent = dev.ctrl_transfer(0x40, request, value, 0, payload, timeout=CTRL_TIMEOUT_MS)
    if sent != len(payload):
        raise IOError(f"short ctrl OUT 0x{request:02x}: {sent}/{len(payload)}")


def bulk_read(dev):
    while True:
        if stop:
            raise KeyboardInterrupt
        try:
            return bytes(dev.read(EP_IN, EP_IN_MAX, timeout=BULK_TIMEOUT_MS))
        except usb.core.USBTimeoutError:
            continue  # idle while waiting for a finger


def read_event(dev, expected=None) -> Event:
    buf = bytearray(bulk_read(dev))
    if len(buf) < FPC_HEADER_SIZE:
        raise IOError(f"short bulk event: {len(buf)} bytes")
    event_id, total_len, status = struct.unpack("<III", buf[:FPC_HEADER_SIZE])
    while len(buf) < total_len:
        buf.extend(bulk_read(dev))
    if expected is not None and event_id != expected:
        raise IOError(f"got event 0x{event_id:08x}, expected 0x{expected:08x}")
    return Event(event_id, total_len, status, bytes(buf[:total_len]))


def tls_write(dev, data):
    for i in range(0, len(data), TLS_FRAGMENT_MAX):
        ctrl_out(dev, CMD_TLS_DATA, 0x01, data[i : i + TLS_FRAGMENT_MAX])


def try_send(dev, request, value, payload=b""):
    """Best-effort vendor OUT; swallows errors used only for cleanup."""
    try:
        ctrl_out(dev, request, value, payload)
    except Exception:
        pass


# --- Sealed PSK --------------------------------------------------------------


def make_tls_key_blob(psk: bytes, pad: bytes | None = None) -> bytes:
    """Seal a TLS PSK into the A921 SET_TLS_KEY blob layout."""
    if len(psk) != TLS_KEY_SIZE:
        raise ValueError(f"TLS PSK must be {TLS_KEY_SIZE} bytes")
    if pad is None:
        pad = os.urandom(TLS_KEY_PAD_SIZE)
    if len(pad) != TLS_KEY_PAD_SIZE:
        raise ValueError(f"TLS key pad must be {TLS_KEY_PAD_SIZE} bytes")

    hmac_key = hmac.new(
        SEAL_KEY,
        b"\x00\x00\x00\x01" + b"application keys\0" + b"\x00\x00\x02\x00",
        hashlib.sha256,
    ).digest()
    crypt_key = hmac.new(
        SEAL_KEY,
        b"\x00\x00\x00\x02" + b"application keys\0" + b"\x00\x00\x02\x00",
        hashlib.sha256,
    ).digest()
    iv = hmac.new(hmac_key, b"iv\0" + b"\x20\x20\xf0\x0d", hashlib.sha256).digest()[:16]

    enc = Cipher(algorithms.AES(crypt_key), modes.CBC(iv)).encryptor()
    encrypted_key = enc.update(psk) + enc.finalize()
    tag = hmac.new(
        hmac_key,
        b"FPC_HMAC_KEY\0" + encrypted_key + SEAL_AAD,
        hashlib.sha256,
    ).digest()

    ct_off = 28
    pad_off = ct_off + len(encrypted_key)
    aad_off = pad_off + len(pad)
    tag_off = aad_off + len(SEAL_AAD)
    header = struct.pack(
        "<7I",
        SEAL_MAGIC,
        ct_off,
        TLS_KEY_SIZE,
        aad_off,
        len(SEAL_AAD),
        tag_off,
        len(tag),
    )
    return header + encrypted_key + pad + SEAL_AAD + tag


# --- TLS over USB ------------------------------------------------------------


class TlsChannel:
    """TLS 1.2 PSK client tunneled over the FPC USB framing.

    The host is the TLS client; we feed ciphertext through MemoryBIOs and
    transmit it via vendor control transfers. No real socket is involved.
    """

    def __init__(self, dev, psk: bytes):
        self.dev = dev
        self.psk = bytes(psk)
        self.in_bio = ssl.MemoryBIO()
        self.out_bio = ssl.MemoryBIO()
        self.plain = bytearray()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers(TLS_CIPHERS)
        ctx.set_psk_client_callback(lambda hint: (TLS_PSK_IDENTITY, self.psk))
        self.ssl = ctx.wrap_bio(self.in_bio, self.out_bio, server_side=False)

    def _flush_out(self):
        out = self.out_bio.read()
        if out:
            tls_write(self.dev, out)

    def _feed_in(self):
        evt = read_event(self.dev, EVT_TLS_RECORD)
        self.in_bio.write(evt.data[FPC_HEADER_SIZE:])

    def handshake(self):
        while True:
            try:
                self.ssl.do_handshake()
                self._flush_out()
                return
            except ssl.SSLWantWriteError:
                self._flush_out()
            except ssl.SSLWantReadError:
                self._flush_out()
                self._feed_in()

    def feed_record(self, body: bytes):
        """Decrypt and discard a TLS record (keepalive during finger wait)."""
        self.in_bio.write(body)
        while True:
            try:
                if not self.ssl.read(EP_IN_MAX):
                    return
            except ssl.SSLWantReadError:
                return
            except ssl.SSLWantWriteError:
                self._flush_out()

    def _read_chunk(self):
        while True:
            try:
                chunk = self.ssl.read(EP_IN_MAX)
                if not chunk:
                    raise IOError("TLS closed")
                return chunk
            except ssl.SSLWantWriteError:
                self._flush_out()
            except ssl.SSLWantReadError:
                self._flush_out()
                self._feed_in()

    def read_plain_event(self) -> Event:
        while len(self.plain) < FPC_HEADER_SIZE:
            self.plain.extend(self._read_chunk())
        event_id, total_len, status = struct.unpack(
            "<III", self.plain[:FPC_HEADER_SIZE]
        )
        while len(self.plain) < total_len:
            self.plain.extend(self._read_chunk())
        data = bytes(self.plain[:total_len])
        del self.plain[:total_len]
        return Event(event_id, total_len, status, data)

    def close_notify(self):
        try:
            self.ssl.unwrap()
        except (ssl.SSLError, OSError):
            pass
        try:
            self._flush_out()
        except Exception:
            pass


# --- Init parsing / output ---------------------------------------------------


def parse_init(data: bytes) -> InitInfo:
    """Parse the INIT_RESULT bulk event (fields per fpc1260-protocol.md)."""
    if len(data) < 38:
        raise IOError(f"short INIT_RESULT event: {len(data)} bytes")
    event_id, _, status = struct.unpack_from("<III", data)
    if event_id != EVT_INIT_RESULT or status != 0:
        raise IOError(f"bad INIT_RESULT event=0x{event_id:08x} status={status}")
    sensor, hw_id, raw_width, raw_height = struct.unpack_from("<HHHH", data, 12)
    firmware = data[20:36].split(b"\0", 1)[0].decode("ascii", "replace")
    (fw_caps,) = struct.unpack_from("<H", data, 36)
    return InitInfo(sensor, hw_id, raw_width, raw_height, firmware, fw_caps)


def rotate_90_ccw(src: bytes, width: int, height: int) -> bytes:
    """Rotate a width x height frame 90 deg CCW (matches the driver)."""
    dst = bytearray(width * height)
    for y in range(height):
        base = y * width
        for x in range(width):
            dst[(width - 1 - x) * height + y] = src[base + x]
    return bytes(dst)


def next_path(out_dir: Path, fmt: str) -> Path:
    ext = {"raw": ".raw", "png": ".png", "pgm": ".pgm"}[fmt]
    i = 0
    while True:
        p = out_dir / f"fingerprint-{i:04d}{ext}"
        if not p.exists():
            return p
        i += 1


def save_image(path: Path, fmt: str, pixels: bytes, width: int, height: int):
    if fmt == "raw":
        path.write_bytes(pixels)
    elif fmt == "png":
        if Image is None:
            raise RuntimeError("Pillow is not installed; cannot write PNG")
        Image.frombytes("L", (width, height), pixels).save(path)
    else:  # pgm
        with path.open("wb") as f:
            f.write(f"P5\n{width} {height}\n255\n".encode())
            f.write(pixels)


def wait_for_finger(dev, tls: TlsChannel):
    """Block until FINGER_DOWN, decrypting/discarding any TLS keepalive."""
    while not stop:
        evt = read_event(dev)
        if evt.event_id == EVT_FINGER_DOWN:
            return
        if evt.event_id == EVT_TLS_RECORD:
            tls.feed_record(evt.data[FPC_HEADER_SIZE:])
        # FINGER_UP and anything else: keep waiting


# --- Main --------------------------------------------------------------------


def main():
    signal.signal(signal.SIGINT, handle_sigint)
    p = argparse.ArgumentParser(
        description="Capture 10a5:a921 (FPC1260) fingerprint images."
    )
    p.add_argument("--out", default="fpc1260-captures", help="output directory")
    p.add_argument("--format", choices=("pgm", "png", "raw"), default="pgm")
    p.add_argument(
        "-n",
        "--count",
        type=int,
        default=0,
        help="stop after N captures (default: until Ctrl+C)",
    )
    args = p.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    dev = open_device()
    tls: TlsChannel | None = None
    try:
        # 1) INIT, wake, and sealed key
        session_id = os.urandom(4)
        ctrl_out(dev, CMD_INIT, 0x01, session_id)
        info = parse_init(read_event(dev, EVT_INIT_RESULT).data)
        if not info.raw_width or not info.raw_height:
            raise IOError("INIT_RESULT did not report image dimensions")
        width, height = info.raw_height, info.raw_width  # after CCW rotation
        print(
            f"sensor: 0x{info.sensor:04x}, hw: 0x{info.hw_id:04x}, "
            f"fw: {info.firmware}, caps: 0x{info.fw_caps:04x}"
        )
        print(f"sensor image: {width}x{height}")
        ctrl_out(dev, CMD_INDICATE_S_STATE, 0x10)  # S0 wake
        ctrl_out(dev, CMD_CLR_IMG, 0x00)  # clear stale image
        psk = os.urandom(TLS_KEY_SIZE)  # fresh PSK each session
        tls_key_data = make_tls_key_blob(psk)

        # 2) Push sealed key, then start TLS (host is the client)
        ctrl_out(dev, CMD_SET_TLS_KEY, 0x00, tls_key_data)
        time.sleep(0.1)  # give the device a moment to process the key
        ctrl_out(dev, CMD_TLS_INIT, 0x01)
        tls = TlsChannel(dev, psk)
        tls.handshake()
        suite = tls.ssl.cipher()
        if suite:
            print(f"TLS established: {suite[0]}")

        # 3) Capture loop
        n = 0
        while not stop:
            ctrl_out(dev, CMD_ARM, 0x01, session_id)
            print("touch the sensor (Ctrl+C to stop)...", flush=True)
            try:
                wait_for_finger(dev, tls)
            finally:
                if stop:
                    try_send(dev, CMD_ABORT, 0x01)

            if stop:
                break

            ctrl_out(dev, CMD_GET_IMG, 0x00)
            evt = tls.read_plain_event()
            if evt.event_id != EVT_IMG or evt.status != 0:
                raise IOError(
                    f"bad image event 0x{evt.event_id:08x} status={evt.status}"
                )
            raw = evt.data[IMAGE_HEADER_SIZE:]
            if len(raw) != info.raw_width * info.raw_height:
                raise IOError(f"unexpected image payload: {len(raw)} bytes")
            pixels = rotate_90_ccw(raw, info.raw_width, info.raw_height)

            ctrl_out(dev, CMD_CLR_IMG, 0x00)  # clear device buffer

            n += 1
            path = next_path(out_dir, args.format)
            save_image(path, args.format, pixels, width, height)
            print(f"saved {path} (#{n})")
            if args.count and n >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if tls is not None:
            tls.close_notify()
        try_send(dev, CMD_ABORT, 0x01)
        try_send(dev, CMD_INDICATE_S_STATE, 0x11)  # SX sleep
        try:
            usb.util.release_interface(dev, IFACE)
            usb.util.dispose_resources(dev)
        except Exception:
            pass


if __name__ == "__main__":
    main()
