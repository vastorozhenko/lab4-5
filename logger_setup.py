import json, logging, os, time
from config import LOG_PATH


class JSONFormatter(logging.Formatter):
    """Один JSON-запис на рядок (JSON Lines). Ключі, паролі, IV/nonce не логуються."""
    def format(self, record):
        base = {
            "ts": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(record.created)),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        if hasattr(record, 'extra') and isinstance(record.extra, dict):
            base.update(record.extra)
        return json.dumps(base, ensure_ascii=False)


def get_logger():
    logger = logging.getLogger('aeslab')
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        os.makedirs(os.path.dirname(LOG_PATH) or '.', exist_ok=True)
        fh = logging.FileHandler(LOG_PATH, encoding='utf-8')
        fh.setFormatter(JSONFormatter())
        logger.addHandler(fh)
    return logger
