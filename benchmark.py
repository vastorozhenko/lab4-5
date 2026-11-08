"""Бенчмарк шифрування/дешифрування: час, пропускна здатність, час CPU, пікова пам'ять.
Запуск: python benchmark.py --modes cbc gcm --sizes 1MB 10MB 100MB --repeat 3
Ключі для бенчмарку випадкові (os.urandom): вимірюється лише AES, без PBKDF2 і без keystore."""
import argparse, csv, os, platform, secrets, statistics, time, tracemalloc
from crypto_aes import MODES
import cryptography

OUT = 'outputs'


def parse_size(s: str) -> int:
    s = s.lower()
    if s.endswith('mb'):
        return int(float(s[:-2]) * 1024 * 1024)
    if s.endswith('kb'):
        return int(float(s[:-2]) * 1024)
    return int(s)


def fmt_size(n: int) -> str:
    return f'{n / 1024 / 1024:g}MB' if n >= 1024 * 1024 else f'{n / 1024:g}KB'


def timed(fn, *a, **kw):
    """Повертає (реальний час, час CPU)."""
    w0, c0 = time.perf_counter(), time.process_time()
    fn(*a, **kw)
    return time.perf_counter() - w0, time.process_time() - c0


def peak_mem(fn, *a, **kw) -> float:
    """Пікова пам'ять Python-алокацій під час виклику, МБ (окремий прогін, не впливає на час)."""
    tracemalloc.start()
    fn(*a, **kw)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return peak / 1024 / 1024


def run(sizes, modes, repeat):
    os.makedirs(OUT, exist_ok=True)
    enc_key, mac_key = secrets.token_bytes(32), secrets.token_bytes(32)
    rows = []
    for size in map(parse_size, sizes):
        src = f'{OUT}/bench_{fmt_size(size)}.bin'
        if not os.path.exists(src) or os.path.getsize(src) != size:
            with open(src, 'wb') as f:
                f.write(secrets.token_bytes(size))
        for mode in modes:
            m = MODES[mode]
            enc_path, dec_path = f'{src}.{mode}.enc', f'{src}.{mode}.dec'
            et, ec, dt, dc = [], [], [], []
            for _ in range(repeat):
                w, c = timed(m['encrypt'], src, enc_path, enc_key, mac_key)
                et.append(w); ec.append(c)
                w, c = timed(m['decrypt'], enc_path, dec_path, enc_key, mac_key)
                dt.append(w); dc.append(c)
            with open(src, 'rb') as a, open(dec_path, 'rb') as b:
                ok = a.read() == b.read()
            enc_mem = peak_mem(m['encrypt'], src, enc_path, enc_key, mac_key)
            dec_mem = peak_mem(m['decrypt'], enc_path, dec_path, enc_key, mac_key)
            overhead = os.path.getsize(enc_path) - size
            mb = size / 1024 / 1024
            row = {
                'size': fmt_size(size), 'mode': m['name'],
                'enc_s': statistics.mean(et), 'enc_sd': statistics.pstdev(et),
                'dec_s': statistics.mean(dt), 'dec_sd': statistics.pstdev(dt),
                'enc_mbps': mb / statistics.mean(et), 'dec_mbps': mb / statistics.mean(dt),
                'enc_cpu_s': statistics.mean(ec), 'dec_cpu_s': statistics.mean(dc),
                'enc_peak_mb': enc_mem, 'dec_peak_mb': dec_mem,
                'overhead_b': overhead, 'ok': ok,
            }
            rows.append(row)
            print(f"{row['size']:>6} {row['mode']:<9} enc {row['enc_s']:.3f}s ({row['enc_mbps']:.0f} MB/s)  "
                  f"dec {row['dec_s']:.3f}s ({row['dec_mbps']:.0f} MB/s)  "
                  f"mem enc/dec {enc_mem:.1f}/{dec_mem:.1f} MB  ok={ok}")
            os.remove(enc_path); os.remove(dec_path)

    with open(f'{OUT}/bench.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()})

    env = (f'Python {platform.python_version()}, cryptography {cryptography.__version__}, '
           f'{platform.system()} {platform.release()}, CPU cores: {os.cpu_count()}, repeat={repeat}')
    lines = [f'Environment: {env}', '',
             '| Size | Mode | Enc avg (s) | Dec avg (s) | Enc MB/s | Dec MB/s | Enc CPU (s) | Dec CPU (s) '
             '| Enc peak RAM (MB) | Dec peak RAM (MB) | Overhead (B) | OK |',
             '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|']
    for r in rows:
        lines.append(f"| {r['size']} | {r['mode']} | {r['enc_s']:.3f} | {r['dec_s']:.3f} | {r['enc_mbps']:.0f} | "
                     f"{r['dec_mbps']:.0f} | {r['enc_cpu_s']:.3f} | {r['dec_cpu_s']:.3f} | {r['enc_peak_mb']:.1f} | "
                     f"{r['dec_peak_mb']:.1f} | {r['overhead_b']} | {'OK' if r['ok'] else 'FAIL'} |")
    with open(f'{OUT}/bench.md', 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'Results -> {OUT}/bench.csv, {OUT}/bench.md')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--sizes', nargs='+', default=['1MB', '10MB', '100MB'])
    ap.add_argument('--modes', nargs='+', choices=list(MODES), default=list(MODES))
    ap.add_argument('--repeat', type=int, default=3)
    a = ap.parse_args()
    run(a.sizes, a.modes, a.repeat)
