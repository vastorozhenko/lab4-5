"""Аналіз JSON-логів: статистика подій і виявлення аномалій.
Запуск: python analyze_logs.py [--log logs/aes.jsonl] [--threshold 3]"""
import argparse, json
from collections import Counter, defaultdict
from config import LOG_PATH

RULES = {
    'dec_integrity_fail': 'HIGH   integrity check failed (tampering/corruption)',
    'WrongPasswordError': 'MEDIUM wrong password',
    'dec_with_revoked_key': 'MEDIUM decryption with revoked key',
    'KeyPolicyError': 'LOW    key policy violation',
    'FormatError': 'LOW    not an encrypted file / bad header',
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', default=LOG_PATH)
    ap.add_argument('--threshold', type=int, default=3,
                    help='alert if the same file/key has this many failures')
    a = ap.parse_args()

    events, findings = Counter(), []
    fails_by_target = defaultdict(int)
    with open(a.log, encoding='utf-8') as f:
        recs = [json.loads(line) for line in f if line.strip()]
    for r in recs:
        events[r['event']] += 1
        for key in (r['event'], r.get('error_type')):
            if key in RULES:
                findings.append((r['ts'], RULES[key], r.get('file') or r.get('label') or '', r.get('error', '')))
                break
        if r['level'] == 'ERROR':
            fails_by_target[r.get('file') or r.get('key_id') or r.get('label')] += 1

    print(f'Records: {len(recs)}  period: {recs[0]["ts"]} .. {recs[-1]["ts"]}' if recs else 'No records')
    print('\nEvents:')
    for e, n in events.most_common():
        print(f'  {e:<22} {n}')
    print('\nFindings:')
    for ts, rule, target, err in findings:
        print(f'  {ts}  {rule:<46} {target}')
    print(f'\nAlerts (>= {a.threshold} failures for the same file/key):')
    alerts = [(t, n) for t, n in fails_by_target.items() if n >= a.threshold]
    for t, n in alerts:
        print(f'  ALERT: {n} failures for {t}: possible brute force or tampering campaign')
    if not alerts:
        print('  none')


if __name__ == '__main__':
    main()
