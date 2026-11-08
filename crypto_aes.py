import os, json, struct
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac as hmac_lib
from cryptography.exceptions import InvalidTag, InvalidSignature
import config
from config import (MAGIC, VERSION, NONCE_BYTES_GCM, IV_BYTES_CBC, HMAC_KEY_BYTES,
                    GCM_TAG_BYTES, HMAC_TAG_BYTES, CHUNK_SIZE)

# Формат файлу:
# CBC: MAGIC(4) | HDRLEN(2) | HEADER(JSON) | IV(16) | CIPHERTEXT | HMAC(32)
# GCM: MAGIC(4) | HDRLEN(2) | HEADER(JSON) | CIPHERTEXT | TAG(16)


class CryptoError(Exception):
    """Базова помилка криптомодуля."""

class FormatError(CryptoError):
    """Файл не є зашифрованим контейнером або пошкоджено заголовок."""

class IntegrityError(CryptoError):
    """Не пройдено перевірку цілісності/автентичності (тег або HMAC)."""


def validate_config():
    """Контроль параметрів шифрування з config.py."""
    assert config.BLOCK_BITS == 128, 'AES block size is always 128 bits'
    assert config.DEFAULT_KEY_BITS in config.ALLOWED_KEY_BITS, 'key length must be 128/192/256'
    assert config.IV_BYTES_CBC == config.BLOCK_BITS // 8, 'CBC IV must equal block size (16 bytes)'
    assert config.NONCE_BYTES_GCM == 12, 'GCM nonce must be 12 bytes (96 bits)'
    assert config.PADDING == 'PKCS7', 'only PKCS7 padding is supported'
    assert config.ITERATIONS >= config.MIN_ITERATIONS, 'PBKDF2 iterations too low'


def _check_key(enc_key: bytes, mac_key: Optional[bytes] = None):
    if len(enc_key) * 8 not in config.ALLOWED_KEY_BITS:
        raise CryptoError(f'Invalid AES key length: {len(enc_key) * 8} bits')
    if mac_key is not None and len(mac_key) != HMAC_KEY_BYTES:
        raise CryptoError(f'Invalid HMAC key length: {len(mac_key)} bytes')


def _pack_header(h: dict) -> bytes:
    blob = json.dumps(h, separators=(',', ':')).encode('utf-8')
    return MAGIC + struct.pack('>H', len(blob)) + blob


def read_header(fp):
    """Повертає (словник заголовка, сирі байти заголовка). Сирі байти потрібні для HMAC."""
    magic = fp.read(4)
    if magic != MAGIC:
        raise FormatError('Bad magic: not an encrypted container')
    raw_len = fp.read(2)
    if len(raw_len) != 2:
        raise FormatError('Truncated header')
    (hdrlen,) = struct.unpack('>H', raw_len)
    blob = fp.read(hdrlen)
    try:
        hdr = json.loads(blob.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise FormatError('Corrupted header')
    return hdr, magic + raw_len + blob


def peek_header(path: str) -> dict:
    with open(path, 'rb') as fp:
        return read_header(fp)[0]


# ---------- AES-CBC + HMAC-SHA256 (Encrypt-then-MAC) ----------

def encrypt_cbc_hmac(in_path: str, out_path: str, enc_key: bytes, mac_key: bytes,
                     key_id: str = '', aad: Optional[bytes] = None):
    _check_key(enc_key, mac_key)
    iv = os.urandom(IV_BYTES_CBC)
    padder = padding.PKCS7(config.BLOCK_BITS).padder()
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    h = {"v": VERSION, "mode": "CBC-HMAC", "alg": f"AES-{len(enc_key) * 8}-CBC",
         "mac": "HMAC-SHA256", "iv": iv.hex(), "key_id": key_id}
    header = _pack_header(h)
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256())
    mac.update(header)          # HMAC(header || IV || ciphertext)
    mac.update(iv)

    with open(in_path, 'rb') as fi, open(out_path, 'wb') as fo:
        fo.write(header)
        fo.write(iv)
        while True:
            chunk = fi.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = enc.update(padder.update(chunk))
            if ct:
                fo.write(ct)
                mac.update(ct)
        ct = enc.update(padder.finalize()) + enc.finalize()
        if ct:
            fo.write(ct)
            mac.update(ct)
        tag = mac.finalize()
        fo.write(tag)
    return len(tag)


def decrypt_cbc_hmac(in_path: str, out_path: str, enc_key: bytes, mac_key: bytes,
                     aad: Optional[bytes] = None):
    _check_key(enc_key, mac_key)
    with open(in_path, 'rb') as fi:
        hdr, raw_header = read_header(fi)
        if hdr.get('mode') != 'CBC-HMAC':
            raise FormatError('Wrong mode in header')
        iv = fi.read(IV_BYTES_CBC)
        data = fi.read()
    if len(data) < HMAC_TAG_BYTES + config.BLOCK_BITS // 8:
        raise FormatError('Truncated ciphertext')
    tag, ciphertext = data[-HMAC_TAG_BYTES:], data[:-HMAC_TAG_BYTES]
    # 1) Спочатку перевірка HMAC (до розшифрування і перевірки паддингу)
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256())
    mac.update(raw_header)
    mac.update(iv)
    mac.update(ciphertext)
    try:
        mac.verify(tag)                       # порівняння за сталий час
    except InvalidSignature:
        raise IntegrityError('HMAC verification failed: ciphertext, IV, header or HMAC was modified')
    # 2) Лише після успішної перевірки: розшифрування і зняття паддингу
    dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    unpad = padding.PKCS7(config.BLOCK_BITS).unpadder()
    try:
        pt = unpad.update(dec.update(ciphertext) + dec.finalize()) + unpad.finalize()
    except ValueError:
        raise IntegrityError('Invalid padding')
    with open(out_path, 'wb') as fo:
        fo.write(pt)


# ---------- AES-GCM (AEAD) ----------

def encrypt_gcm(in_path: str, out_path: str, enc_key: bytes, mac_key: bytes = None,
                key_id: str = '', aad: Optional[bytes] = None):
    _check_key(enc_key)
    nonce = os.urandom(NONCE_BYTES_GCM)
    enc = Cipher(algorithms.AES(enc_key), modes.GCM(nonce)).encryptor()
    h = {"v": VERSION, "mode": "GCM", "alg": f"AES-{len(enc_key) * 8}-GCM",
         "nonce": nonce.hex(), "key_id": key_id}
    header = _pack_header(h)
    # Заголовок автентифікується як AAD, разом із AAD користувача (якщо задано)
    enc.authenticate_additional_data(header + (aad or b''))
    with open(in_path, 'rb') as fi, open(out_path, 'wb') as fo:
        fo.write(header)
        while True:
            chunk = fi.read(CHUNK_SIZE)
            if not chunk:
                break
            fo.write(enc.update(chunk))
        fo.write(enc.finalize())
        fo.write(enc.tag)
    return len(enc.tag)


def decrypt_gcm(in_path: str, out_path: str, enc_key: bytes, mac_key: bytes = None,
                aad: Optional[bytes] = None):
    _check_key(enc_key)
    with open(in_path, 'rb') as fi:
        hdr, raw_header = read_header(fi)
        if hdr.get('mode') != 'GCM':
            raise FormatError('Wrong mode in header')
        try:
            nonce = bytes.fromhex(hdr['nonce'])
        except (KeyError, ValueError):
            raise FormatError('Corrupted header: bad nonce')
        if len(nonce) != NONCE_BYTES_GCM:
            raise FormatError('Corrupted header: bad nonce length')
        data = fi.read()
    if len(data) < GCM_TAG_BYTES:
        raise FormatError('Truncated ciphertext')
    tag, ciphertext = data[-GCM_TAG_BYTES:], data[:-GCM_TAG_BYTES]
    dec = Cipher(algorithms.AES(enc_key), modes.GCM(nonce, tag)).decryptor()
    dec.authenticate_additional_data(raw_header + (aad or b''))
    try:
        pt = dec.update(ciphertext) + dec.finalize()
    except InvalidTag:
        raise IntegrityError('GCM InvalidTag: ciphertext, nonce, header, AAD or tag was modified')
    # Відкритий текст записується лише після успішної перевірки тегу
    with open(out_path, 'wb') as fo:
        fo.write(pt)


# ---------- Реєстр режимів (розширюваність) ----------
# Щоб додати новий режим (наприклад, CTR+HMAC), достатньо написати пару функцій
# encrypt_x/decrypt_x з тією самою сигнатурою і додати запис у MODES.
MODES = {
    "cbc": {"name": "CBC-HMAC", "encrypt": encrypt_cbc_hmac, "decrypt": decrypt_cbc_hmac,
            "iv_bytes": IV_BYTES_CBC, "padding": config.PADDING, "integrity": "HMAC-SHA256 (32 B)"},
    "gcm": {"name": "GCM", "encrypt": encrypt_gcm, "decrypt": decrypt_gcm,
            "iv_bytes": NONCE_BYTES_GCM, "padding": "none (stream)", "integrity": "GCM tag (16 B)"},
}
HEADER_TO_MODE = {v["name"]: k for k, v in MODES.items()}


def describe_params() -> str:
    lines = [f"AES block size : {config.BLOCK_BITS} bits (fixed by AES standard)",
             f"Key length     : {config.DEFAULT_KEY_BITS} bits (allowed: {config.ALLOWED_KEY_BITS})",
             f"KDF            : PBKDF2-HMAC-SHA256, {config.ITERATIONS} iterations, salt {config.SALT_BYTES} B",
             f"Key policy     : max {config.MAX_USES} encryptions or {config.MAX_AGE_DAYS} days per key", ""]
    lines.append(f"{'mode':<5} {'name':<9} {'IV/nonce':<9} {'padding':<14} integrity")
    for k, m in MODES.items():
        lines.append(f"{k:<5} {m['name']:<9} {str(m['iv_bytes']) + ' B':<9} {m['padding']:<14} {m['integrity']}")
    return "\n".join(lines)
