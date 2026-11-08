import argparse, getpass, os, sys, time, shlex
from logger_setup import get_logger
from key_manager import KeyManager, KeyPolicyError, WrongPasswordError
from crypto_aes import (MODES, HEADER_TO_MODE, CryptoError, FormatError, IntegrityError,
                        peek_header, validate_config, describe_params)

logger = get_logger()


def log(level, event, **fields):
    getattr(logger, level)(event, extra={'extra': fields})


def ask_password(args_password):
    """Пароль краще вводити інтерактивно (не потрапляє в історію команд і список процесів)."""
    return args_password if args_password else getpass.getpass('Password: ')


# ---------- Операції (спільні для CLI і REPL) ----------

def do_encrypt(km, meta, enc_key, mac_key, mode, infile, outfile, aad=None):
    size = os.path.getsize(infile)
    log('info', 'enc_start', mode=MODES[mode]['name'], file=infile, size=size, key_id=meta['key_id'])
    try:
        km.check_can_encrypt(meta)
        t0 = time.perf_counter()
        taglen = MODES[mode]['encrypt'](infile, outfile, enc_key, mac_key, key_id=meta['key_id'], aad=aad)
        dt = time.perf_counter() - t0
    except (CryptoError, KeyPolicyError, OSError) as e:
        log('error', 'enc_error', mode=MODES[mode]['name'], file=infile, key_id=meta['key_id'],
            error_type=type(e).__name__, error=str(e))
        print(f'ERROR [{type(e).__name__}]: {e}')
        return False
    km.inc_use(meta['key_id'])
    log('info', 'enc_ok', mode=MODES[mode]['name'], file=infile, out=outfile, size=size,
        sec=round(dt, 4), taglen=taglen, key_id=meta['key_id'], key_uses=meta['uses'])
    print(f'Encrypted [{MODES[mode]["name"]}] {infile} -> {outfile} in {dt:.3f}s')
    return True


def do_decrypt(km, label, password, infile, outfile, mode=None, aad=None, keys=None):
    """mode=None: режим береться із заголовка файлу. keys: вже виведені ключі (для REPL)."""
    size = os.path.getsize(infile) if os.path.exists(infile) else 0
    fields = {'file': infile, 'size': size}
    try:
        hdr = peek_header(infile)
        file_mode = HEADER_TO_MODE.get(hdr.get('mode'))
        if file_mode is None:
            raise FormatError(f'Unknown mode in header: {hdr.get("mode")}')
        if mode and mode != file_mode:
            raise FormatError(f'Mode mismatch: requested {mode}, file is {file_mode}')
        mode = file_mode
        fields.update(mode=MODES[mode]['name'], key_id=hdr.get('key_id'))
        log('info', 'dec_start', **fields)
        meta, enc_key, mac_key = keys if keys else km.derive_keypair(label, password)
        if hdr.get('key_id') and hdr['key_id'] != meta['key_id']:
            other = next((k for k in km.db['keys'] if k['key_id'] == hdr['key_id']), None)
            if other:
                raise KeyPolicyError(f'File was encrypted with another key: "{other["label"]}"')
            # невідомий key_id: заголовок міг бути змінений, рішення приймає перевірка HMAC/тегу
        if km.state(meta)['state'] == 'revoked':
            log('warning', 'dec_with_revoked_key', **fields)
        t0 = time.perf_counter()
        MODES[mode]['decrypt'](infile, outfile, enc_key, mac_key, aad=aad)
        dt = time.perf_counter() - t0
    except IntegrityError as e:
        log('error', 'dec_integrity_fail', tag_valid=False, error_type=type(e).__name__, error=str(e), **fields)
        print(f'ERROR [{type(e).__name__}]: {e}. Output file was NOT written.')
        return False
    except (CryptoError, KeyPolicyError, OSError) as e:
        log('error', 'dec_error', error_type=type(e).__name__, error=str(e), **fields)
        print(f'ERROR [{type(e).__name__}]: {e}')
        return False
    log('info', 'dec_ok', tag_valid=True, out=outfile, sec=round(dt, 4), **fields)
    print(f'Decrypted [{MODES[mode]["name"]}] {infile} -> {outfile} in {dt:.3f}s, integrity OK')
    return True


# ---------- Команди CLI ----------

def cmd_key(args):
    km = KeyManager()
    try:
        if args.action == 'new':
            meta = km.new_key(args.label, ask_password(args.password), key_bits=args.bits)
            log('info', 'key_new', label=meta['label'], key_id=meta['key_id'], key_bits=meta['key_bits'])
            print('CREATED', meta)
        elif args.action == 'list':
            print(f"{'label':<12} {'key_id':<17} {'bits':<5} {'uses':<10} {'state':<10} created")
            for k in km.list_keys():
                created = time.strftime('%Y-%m-%d %H:%M', time.localtime(k['created_at']))
                print(f"{k['label']:<12} {k['key_id']:<17} {k.get('key_bits', 256):<5} "
                      f"{str(k['uses']) + '/' + str(k.get('max_uses', '-')):<10} {k['state']:<10} {created}")
        elif args.action == 'revoke':
            meta = km.revoke(label=args.label, key_id=args.id)
            log('warning', 'key_revoke', label=meta['label'], key_id=meta['key_id'])
            print('REVOKED', meta['label'], meta['key_id'])
    except KeyPolicyError as e:
        log('error', 'key_error', action=args.action, label=getattr(args, 'label', None), error_type=type(e).__name__, error=str(e))
        print(f'ERROR [{type(e).__name__}]: {e}')
        sys.exit(1)


def cmd_enc(args):
    km = KeyManager()
    try:
        meta, enc_key, mac_key = km.derive_keypair(args.label, ask_password(args.password))
    except KeyPolicyError as e:
        log('error', 'enc_error', file=args.infile, error_type=type(e).__name__, error=str(e))
        print(f'ERROR [{type(e).__name__}]: {e}')
        sys.exit(1)
    aad = args.aad.encode('utf-8') if args.aad else None
    if not do_encrypt(km, meta, enc_key, mac_key, args.mode, args.infile, args.outfile, aad):
        sys.exit(1)


def cmd_dec(args):
    km = KeyManager()
    aad = args.aad.encode('utf-8') if args.aad else None
    if not do_decrypt(km, args.label, ask_password(args.password), args.infile, args.outfile, args.mode, aad):
        sys.exit(1)


def cmd_bench(args):
    import benchmark
    benchmark.run(args.sizes, args.modes, args.repeat)


# ---------- REPL: зміна режиму без перезапуску ----------

def repl():
    print('AES-Lab REPL. commands: mode [cbc|gcm], params, enc IN OUT, dec IN OUT, quit')
    mode = 'gcm'
    km = KeyManager()
    label = input('Key label: ').strip()
    try:
        keys = km.derive_keypair(label, getpass.getpass('Password: '))
    except KeyPolicyError as e:
        log('error', 'repl_login_fail', label=label, error_type=type(e).__name__, error=str(e))
        print(f'ERROR [{type(e).__name__}]: {e}')
        return
    log('info', 'repl_start', label=label, key_id=keys[0]['key_id'])
    while True:
        try:
            cmd = shlex.split(input(f'[{mode}]> '))
        except EOFError:
            break
        if not cmd:
            continue
        if cmd[0] in ('quit', 'exit'):
            break
        if cmd[0] == 'mode' and len(cmd) >= 2 and cmd[1] in MODES:
            log('info', 'mode_change', old=MODES[mode]['name'], new=MODES[cmd[1]]['name'])
            mode = cmd[1]
            print('mode ->', mode, f'({MODES[mode]["name"]})')
        elif cmd[0] == 'params':
            print(describe_params())
        elif cmd[0] == 'enc' and len(cmd) >= 3:
            meta, enc_key, mac_key = keys
            do_encrypt(km, meta, enc_key, mac_key, mode, cmd[1], cmd[2])
        elif cmd[0] == 'dec' and len(cmd) >= 3:
            do_decrypt(km, label, None, cmd[1], cmd[2], mode=None, keys=keys)
        else:
            print('unknown command')
    log('info', 'repl_stop', label=label)


def main():
    validate_config()
    p = argparse.ArgumentParser(description='Lab 4-5: AES-CBC+HMAC / AES-GCM file encryption')
    sp = p.add_subparsers(dest='cmd', required=True)

    pk = sp.add_parser('key', help='key management')
    pksp = pk.add_subparsers(dest='action', required=True)
    pk_new = pksp.add_parser('new')
    pk_new.add_argument('--label', required=True)
    pk_new.add_argument('--password', help='if omitted, asked interactively')
    pk_new.add_argument('--bits', type=int, choices=[128, 192, 256], default=256)
    pksp.add_parser('list')
    pk_rev = pksp.add_parser('revoke')
    g = pk_rev.add_mutually_exclusive_group(required=True)
    g.add_argument('--label')
    g.add_argument('--id')

    for name in ('enc', 'dec'):
        pp = sp.add_parser(name)
        pp.add_argument('--in', dest='infile', required=True)
        pp.add_argument('--out', dest='outfile', required=True)
        pp.add_argument('--mode', choices=list(MODES), required=(name == 'enc'),
                        help='for dec: optional, taken from file header')
        pp.add_argument('--label', required=True)
        pp.add_argument('--password', help='if omitted, asked interactively')
        pp.add_argument('--aad', help='additional authenticated data (must be the same for dec)')

    pb = sp.add_parser('bench')
    pb.add_argument('--sizes', nargs='+', default=['1MB', '10MB', '100MB'])
    pb.add_argument('--modes', nargs='+', choices=list(MODES), default=list(MODES))
    pb.add_argument('--repeat', type=int, default=3)

    sp.add_parser('params', help='show encryption parameters')
    sp.add_parser('shell', help='interactive mode, change mode without restart')

    args = p.parse_args()
    {'key': cmd_key, 'enc': cmd_enc, 'dec': cmd_dec, 'bench': cmd_bench,
     'params': lambda a: print(describe_params()), 'shell': lambda a: repl()}[args.cmd](args)


if __name__ == '__main__':
    main()
