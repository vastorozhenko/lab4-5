# Параметри за замовчуванням (інтерфейс налаштування параметрів шифрування).
# Перевіряються функцією validate_config() у crypto_aes.py під час запуску.

# --- KDF ---
ITERATIONS = 310_000          # PBKDF2-HMAC-SHA256 (вимога курсу: >= 200k)
MIN_ITERATIONS = 200_000
SALT_BYTES = 16
MIN_PASSWORD_LEN = 12         # мінімальна довжина пароля для нового ключа

# --- Ключі ---
DEFAULT_KEY_BITS = 256        # AES-256
ALLOWED_KEY_BITS = (128, 192, 256)
HMAC_KEY_BYTES = 32           # окремий ключ HMAC-SHA256 для CBC

# --- Параметри режимів ---
BLOCK_BITS = 128              # розмір блоку AES фіксований стандартом (FIPS 197)
IV_BYTES_CBC = 16             # IV для CBC = розмір блоку, випадковий
NONCE_BYTES_GCM = 12          # nonce для GCM, 96 біт (NIST SP 800-38D)
GCM_TAG_BYTES = 16            # тег автентифікації GCM, 128 біт
HMAC_TAG_BYTES = 32           # HMAC-SHA256
PADDING = "PKCS7"             # паддинг для CBC

# --- Життєвий цикл ключа (ротація) ---
MAX_USES = 1000               # після N шифрувань ключ не можна використовувати для нових шифрувань
MAX_AGE_DAYS = 90             # після N днів ключ не можна використовувати для нових шифрувань

# --- Інше ---
CHUNK_SIZE = 1024 * 1024
MAGIC = b'ALAB'
VERSION = 1
LOG_PATH = 'logs/aes.jsonl'
KEYSTORE_PATH = 'keystore.json'
