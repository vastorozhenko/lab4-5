"""Імітація підміни зашифрованого файлу: змінюється один байт у вибраній ділянці контейнера.
Приклад: python tamper_demo.py --file outputs/sample.enc --target tag
Результат: outputs/sample.enc.tampered (оригінал не змінюється)."""
import argparse, random
from crypto_aes import read_header
from config import IV_BYTES_CBC, HMAC_TAG_BYTES, GCM_TAG_BYTES


def regions(path: str) -> dict:
    """Межі ділянок контейнера: header, iv (лише CBC), ciphertext, tag."""
    with open(path, 'rb') as f:
        hdr, raw = read_header(f)
        total = f.seek(0, 2)
    h_end = len(raw)
    if hdr['mode'] == 'CBC-HMAC':
        iv_end, tag_len = h_end + IV_BYTES_CBC, HMAC_TAG_BYTES
        r = {'header': (0, h_end), 'iv': (h_end, iv_end)}
    else:
        iv_end, tag_len = h_end, GCM_TAG_BYTES
        r = {'header': (0, h_end)}
    r['ciphertext'] = (iv_end, total - tag_len)
    r['tag'] = (total - tag_len, total)
    return hdr['mode'], r


def tamper(path: str, target: str, out: str = None, quiet: bool = False) -> str:
    mode, r = regions(path)
    if target not in r:
        raise SystemExit(f'target "{target}" not available for {mode}; choose from {list(r)}')
    start, end = r[target]
    if target == 'header':
        start = 6                      # не чіпаємо MAGIC/HDRLEN, змінюємо вміст JSON-заголовка
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    i = random.randrange(start, end)
    old = data[i]
    data[i] ^= 0x01                    # інвертуємо один біт
    out = out or path + '.tampered'
    with open(out, 'wb') as f:
        f.write(data)
    if quiet:
        return out
    print(f'mode={mode} target={target} offset={i} (region {start}-{end - 1}) '
          f'byte 0x{old:02x} -> 0x{data[i]:02x}')
    print('tampered ->', out)
    return out


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', required=True)
    ap.add_argument('--target', choices=['ciphertext', 'tag', 'iv', 'header'], default='ciphertext')
    ap.add_argument('--out')
    args = ap.parse_args()
    tamper(args.file, args.target, args.out)
