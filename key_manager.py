import os, json, time, hashlib, hmac
from typing import Dict
from config import (KEYSTORE_PATH, ITERATIONS, MIN_ITERATIONS, SALT_BYTES, HMAC_KEY_BYTES,
                    DEFAULT_KEY_BITS, ALLOWED_KEY_BITS, MIN_PASSWORD_LEN, MAX_USES, MAX_AGE_DAYS)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class KeyPolicyError(Exception):
    """Помилка керування ключами (немає ключа, політика, неправильний пароль)."""

class WrongPasswordError(KeyPolicyError):
    pass


class KeyManager:
    """Keystore зберігає лише метадані (salt, ітерації, алгоритм, key_id, статус).
    Самі ключі ніколи не записуються на диск: вони щоразу виводяться з пароля через PBKDF2."""

    def __init__(self, path=KEYSTORE_PATH):
        self.path = path
        self.db = {"keys": []}
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                self.db = json.load(f)

    def save(self):
        # Файл створюється з правами 600 (читання/запис лише власником)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(self.db, f, ensure_ascii=False, indent=2)
        os.chmod(self.path, 0o600)

    @staticmethod
    def _derive(password: bytes, salt: bytes, length: int, iterations: int):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
        return kdf.derive(password)

    @staticmethod
    def _key_id(enc_key: bytes) -> str:
        return hashlib.sha256(enc_key).hexdigest()[:16]

    # ---------- Ініціалізація ключа ----------
    def new_key(self, label: str, password: str, key_bits: int = DEFAULT_KEY_BITS,
                iterations: int = ITERATIONS) -> Dict:
        if key_bits not in ALLOWED_KEY_BITS:
            raise KeyPolicyError(f'Key length must be one of {ALLOWED_KEY_BITS} bits')
        if iterations < MIN_ITERATIONS:
            raise KeyPolicyError(f'PBKDF2 iterations must be >= {MIN_ITERATIONS}')
        if len(password) < MIN_PASSWORD_LEN:
            raise KeyPolicyError(f'Password must be at least {MIN_PASSWORD_LEN} characters')
        if any(k['label'] == label for k in self.db['keys']):
            raise KeyPolicyError(f'Label "{label}" already exists: use a new label for a new key')
        salt = os.urandom(SALT_BYTES)                     # випадковий salt для кожного ключа
        enc_len = key_bits // 8
        # Для CBC+HMAC потрібні два незалежні ключі: enc_key і mac_key
        material = self._derive(password.encode('utf-8'), salt, enc_len + HMAC_KEY_BYTES, iterations)
        enc_key = material[:enc_len]
        if len(enc_key) * 8 != key_bits:                  # контроль довжини ключа
            raise KeyPolicyError('Derived key has wrong length')
        key_id = self._key_id(enc_key)
        # Запобігання повторному використанню того самого ключового матеріалу
        if any(k['key_id'] == key_id for k in self.db['keys']):
            raise KeyPolicyError('Key reuse prohibited: identical key material detected')
        now = int(time.time())
        meta = {
            "label": label,
            "key_id": key_id,
            "key_bits": key_bits,
            "salt": salt.hex(),
            "iterations": iterations,
            "kdf": "PBKDF2-HMAC-SHA256",
            "created_at": now,
            "expires_at": now + MAX_AGE_DAYS * 86400,
            "max_uses": MAX_USES,
            "uses": 0,
            "status": "active",
        }
        self.db['keys'].append(meta)
        self.save()
        return meta

    def list_keys(self):
        return [self.state(k) | k for k in self.db['keys']]

    def find(self, label: str = None, key_id: str = None) -> Dict:
        for k in self.db['keys']:
            if (label and k['label'] == label) or (key_id and k['key_id'] == key_id):
                return k
        raise KeyPolicyError(f'Key not found: {label or key_id}')

    # ---------- Отримання ключа з пароля ----------
    def derive_keypair(self, label: str = None, password: str = '', key_id: str = None):
        meta = self.find(label, key_id)
        salt = bytes.fromhex(meta['salt'])
        enc_len = meta.get('key_bits', 256) // 8
        material = self._derive(password.encode('utf-8'), salt, enc_len + HMAC_KEY_BYTES, meta['iterations'])
        enc_key, mac_key = material[:enc_len], material[enc_len:]
        # key_id = SHA-256(enc_key)[:16]: якщо не збігається, пароль неправильний
        if not hmac.compare_digest(self._key_id(enc_key), meta['key_id']):
            raise WrongPasswordError('Wrong password for key "%s"' % meta['label'])
        return meta, enc_key, mac_key

    # ---------- Життєвий цикл ----------
    @staticmethod
    def state(meta: Dict) -> Dict:
        if meta.get('status') == 'revoked':
            return {"state": "revoked"}
        if meta['uses'] >= meta.get('max_uses', MAX_USES):
            return {"state": "exhausted"}
        if time.time() > meta.get('expires_at', float('inf')):
            return {"state": "expired"}
        return {"state": "active"}

    def check_can_encrypt(self, meta: Dict):
        """Нові шифрування дозволені лише активним ключем. Розшифрування старих даних дозволене завжди."""
        st = self.state(meta)['state']
        if st != 'active':
            raise KeyPolicyError(f'Key "{meta["label"]}" is {st}: create a new key (key new) for new encryptions')

    def inc_use(self, key_id: str):
        for k in self.db['keys']:
            if k['key_id'] == key_id:
                k['uses'] += 1
                break
        self.save()

    def revoke(self, label: str = None, key_id: str = None) -> Dict:
        meta = self.find(label, key_id)
        meta['status'] = 'revoked'
        meta['revoked_at'] = int(time.time())
        self.save()
        return meta
