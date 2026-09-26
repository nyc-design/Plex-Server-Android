#!/usr/bin/env python3
"""Local Plex Android crypto-library compatibility patcher. No network uploads."""
from __future__ import annotations
import argparse
import datetime
import hashlib
import io
import json
import os
import re
import struct
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from elftools.elf.elffile import ELFFile

VERSION = '0.1.0'
ORIGINAL = 'com.plexapp.mediaserver.smb'
PATCHED = 'com.plexapp.mediaserver.mod'
RENAMES = {'libcrypto.so': 'libplexcr.so', 'libssl.so': 'libpsl.so'}
ALG = 0x0103  # RSASSA-PKCS1-v1_5 with SHA-256, APK Signature Scheme v2
MAGIC = b'APK Sig Block 42'

def u32(n): return struct.pack('<I', n)
def lp(data): return u32(len(data)) + data

def take_lp(data, pos=0):
    if pos + 4 > len(data): raise ValueError('Truncated length field')
    size = struct.unpack_from('<I', data, pos)[0]
    end = pos + 4 + size
    if end > len(data): raise ValueError('Truncated length-prefixed field')
    return data[pos + 4:end], end

def zip_sections(data):
    pos = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
    if pos < 0 or pos + 22 > len(data): raise ValueError('Missing ZIP end record')
    comment = struct.unpack_from('<H', data, pos + 20)[0]
    if pos + 22 + comment != len(data): raise ValueError('Invalid ZIP end record')
    cd_size, cd_pos = struct.unpack_from('<II', data, pos + 12)
    if cd_pos + cd_size != pos: raise ValueError('ZIP64 or invalid central directory unsupported')
    return cd_pos, pos

def content_digest(regions):
    chunks = []
    for region in regions:
        for i in range(0, len(region), 1024 * 1024):
            chunk = region[i:i + 1024 * 1024]
            chunks.append(hashlib.sha256(b'\xa5' + u32(len(chunk)) + chunk).digest())
    return hashlib.sha256(b'\x5a' + u32(len(chunks)) + b''.join(chunks)).digest()

def load_identity(folder):
    folder.mkdir(parents=True, exist_ok=True)
    key_file, cert_file = folder / 'signing-key.pem', folder / 'signing-cert.der'
    if key_file.exists() != cert_file.exists(): raise ValueError('Key and certificate must both exist')
    if key_file.exists():
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        cert_der = cert_file.read_bytes()
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Android compatibility build')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650)).sign(key, hashes.SHA256()))
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
        cert_file.write_bytes(cert_der)
    cert = x509.load_der_x509_certificate(cert_der)
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError('Signing key does not match certificate')
    return key, cert_der

def sign_apk(data, key, cert_der):
    cd, end = zip_sections(data)
    digest = content_digest([data[:cd], data[cd:end], data[end:]])
    signed_data = lp(lp(u32(ALG) + lp(digest))) + lp(lp(cert_der)) + lp(b'')
    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    pub = key.public_key().public_bytes(serialization.Encoding.DER,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
    signer = lp(signed_data) + lp(lp(u32(ALG) + lp(signature))) + lp(pub)
    value = lp(lp(signer))
    pair = struct.pack('<Q', len(value) + 4) + u32(0x7109871a) + value
    size = struct.pack('<Q', len(pair) + 24)
    block = size + pair + size + MAGIC
    eocd = bytearray(data[end:])
    struct.pack_into('<I', eocd, 16, cd + len(block))
    return data[:cd] + block + data[cd:end] + eocd

def verify_apk(data):
    """Verify our v2 RSA signature, signing certificate, and APK content digest."""
    data = bytes(data)
    cd, end = zip_sections(data)
    if data[cd - 16:cd] != MAGIC: raise ValueError('Missing v2 signing block')
    size = struct.unpack_from('<Q', data, cd - 24)[0]
    begin = cd - size - 8
    if begin < 0 or struct.unpack_from('<Q', data, begin)[0] != size:
        raise ValueError('Invalid signing block size')
    pos, value = begin + 8, None
    while pos < cd - 24:
        n = struct.unpack_from('<Q', data, pos)[0]
        if n < 4 or pos + 8 + n > cd - 24: raise ValueError('Invalid signing pair')
        if struct.unpack_from('<I', data, pos + 8)[0] == 0x7109871a:
            value = data[pos + 12:pos + 8 + n]
        pos += 8 + n
    if value is None: raise ValueError('Missing v2 signer')
    signers, _ = take_lp(value)
    signer, _ = take_lp(signers)
    signed_data, p = take_lp(signer)
    signatures, p = take_lp(signer, p)
    public_der, _ = take_lp(signer, p)
    signature_record, _ = take_lp(signatures)
    if struct.unpack_from('<I', signature_record)[0] != ALG: raise ValueError('Unexpected signature algorithm')
    sig, _ = take_lp(signature_record, 4)
    public = serialization.load_der_public_key(public_der)
    public.verify(sig, signed_data, padding.PKCS1v15(), hashes.SHA256())
    digests, p = take_lp(signed_data)
    certs, _ = take_lp(signed_data, p)
    cert_der, _ = take_lp(certs)
    if x509.load_der_x509_certificate(cert_der).public_key().public_numbers() != public.public_numbers():
        raise ValueError('Signer certificate mismatch')
    record, _ = take_lp(digests)
    if struct.unpack_from('<I', record)[0] != ALG: raise ValueError('Unexpected digest algorithm')
    expected, _ = take_lp(record, 4)
    eocd = bytearray(data[end:])
    struct.pack_into('<I', eocd, 16, begin)
    actual = content_digest([data[:begin], data[cd:end], eocd])
    if expected != actual: raise ValueError('APK content digest mismatch')
    return hashlib.sha256(cert_der).hexdigest()

def patch_elf(data):
    elf = ELFFile(io.BytesIO(data))
    if elf['e_machine'] != 'EM_AARCH64': raise ValueError('Only arm64 native code is supported')
    section, dynamic = elf.get_section_by_name('.dynstr'), elf.get_section_by_name('.dynamic')
    if section is None or dynamic is None: raise ValueError('ELF lacks dynamic string table')
    result, edits = bytearray(data), []
    for tag in dynamic.iter_tags():
        if tag.entry.d_tag not in ('DT_NEEDED', 'DT_SONAME'): continue
        old = tag.needed if tag.entry.d_tag == 'DT_NEEDED' else tag.soname
        if old not in RENAMES: continue
        new = RENAMES[old]
        assert len(old) == len(new)
        offset = section['sh_offset'] + tag.entry.d_val
        if data[offset:offset + len(old) + 1] != old.encode() + b'\0':
            raise ValueError('Unexpected ELF string offset')
        result[offset:offset + len(old)] = new.encode()
        edits.append({'kind': tag.entry.d_tag, 'from': old, 'to': new})
    return bytes(result), edits

def validate_archive(z):
    names = z.namelist()
    if len(names) != len(set(names)): raise ValueError('Duplicate ZIP entries')
    for n in names:
        p = PurePosixPath(n)
        if p.is_absolute() or '..' in p.parts or '\\' in n:
            raise ValueError('Unsafe archive entry')
    if sum(i.file_size for i in z.infolist()) > 2 * 1024**3:
        raise ValueError('Archive exceeds 2 GiB uncompressed limit')

def replace_package(data):
    return data.replace(ORIGINAL.encode(), PATCHED.encode()).replace(
        ORIGINAL.encode('utf-16le'), PATCHED.encode('utf-16le'))

def rebuild_apk(raw, key, cert_der):
    buf, edits = io.BytesIO(), []
    with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(buf, 'w') as dest:
        validate_archive(source)
        manifest = source.read('AndroidManifest.xml')
        if ORIGINAL.encode() not in manifest and ORIGINAL.encode('utf-16le') not in manifest:
            raise ValueError('APK is not the original Plex SHIELD server package')
        for entry in source.infolist():
            name = entry.filename
            # Preserve licenses and all other META-INF contents; remove only old signatures.
            if re.fullmatch(r'META-INF/[^/]+\.(SF|RSA|DSA|EC)', name, re.I) or name.upper() == 'META-INF/MANIFEST.MF' or name == 'stamp-cert-sha256':
                continue
            data = source.read(name)
            if name in ('AndroidManifest.xml', 'resources.arsc'):
                data = replace_package(data)
            elif name.endswith('.dex') and ORIGINAL.encode() in data:
                data = bytearray(replace_package(data))
                data[12:32] = hashlib.sha1(data[32:]).digest()
                struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
            elif name.startswith('lib/') and name.endswith('.so'):
                if not name.startswith('lib/arm64-v8a/'):
                    raise ValueError('Only arm64 APK sets are supported')
                data, changes = patch_elf(data)
                if changes: edits.append({'file': name, 'changes': changes})
                basename = PurePosixPath(name).name
                name = 'lib/arm64-v8a/' + RENAMES.get(basename, basename)
            info = zipfile.ZipInfo(name, entry.date_time)
            info.compress_type, info.external_attr = entry.compress_type, entry.external_attr
            if info.compress_type == zipfile.ZIP_STORED:
                align = 16384 if name.endswith('.so') else 4
                amount = (-(buf.tell() + 30 + len(name.encode()))) % align
                if amount:
                    if amount < 4: amount += align
                    info.extra = struct.pack('<HH', 0xCAFE, amount - 4) + bytes(amount - 4)
            dest.writestr(info, data)
    result = sign_apk(buf.getvalue(), key, cert_der)
    verify_apk(result)
    with zipfile.ZipFile(io.BytesIO(result)) as z:
        if z.testzip() is not None: raise ValueError('Rebuilt ZIP failed CRC check')
    return result, edits

def adb(args, serial=None, **kwargs):
    return subprocess.run(['adb'] + (['-s', serial] if serial else []) + args, check=True, **kwargs)

def get_sources(args, temporary):
    if args.from_device:
        paths = adb(['shell', 'pm', 'path', ORIGINAL], args.serial, capture_output=True, text=True).stdout.splitlines()
        if not paths: raise ValueError('Original Plex server is not installed')
        result = []
        for line in paths:
            if not line.startswith('package:'): raise ValueError('Unexpected package path')
            remote = line.removeprefix('package:').strip()
            local = temporary / PurePosixPath(remote).name
            adb(['pull', remote, str(local)], args.serial, stdout=subprocess.DEVNULL)
            result.append(local)
        return result
    path = args.input.resolve()
    if path.is_dir(): return sorted(path.glob('*.apk'))
    if path.suffix.lower() == '.apk': return [path]
    result = []
    with zipfile.ZipFile(path) as z:
        validate_archive(z)
        for name in z.namelist():
            if name.endswith('.apk'):
                out = temporary / PurePosixPath(name).name
                if out.exists(): raise ValueError('APK filename collision')
                out.write_bytes(z.read(name)); result.append(out)
    if not result: raise ValueError('No APKs found in input')
    return result

def build(args):
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()): raise ValueError('Output directory must be empty')
    output.mkdir(parents=True, exist_ok=True)
    key, cert = load_identity(args.keys.resolve())
    report = {'patcherVersion': VERSION, 'originalPackage': ORIGINAL, 'patchedPackage': PATCHED,
              'certificateSHA256': hashlib.sha256(cert).hexdigest(), 'files': []}
    with tempfile.TemporaryDirectory(prefix='plex-compat-') as t:
        sources = get_sources(args, Path(t))
        if not sources: raise ValueError('No input APKs')
        for source in sources:
            if not re.fullmatch(r'[A-Za-z0-9_.-]+\.apk', source.name): raise ValueError('Unsupported APK filename')
            raw = source.read_bytes()
            result, edits = rebuild_apk(raw, key, cert)
            (output / source.name).write_bytes(result)
            report['files'].append({'name': source.name, 'inputSHA256': hashlib.sha256(raw).hexdigest(),
                'outputSHA256': hashlib.sha256(result).hexdigest(), 'nativeEdits': edits})
    if not any(f['nativeEdits'] for f in report['files']):
        raise ValueError('No native crypto references patched; input may lack its arm64 split')
    (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    names = [f['name'] for f in report['files']]
    with zipfile.ZipFile(output / 'plex-android-compat.apks', 'w', compression=zipfile.ZIP_STORED) as z:
        for name in names:
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            z.writestr(info, (output / name).read_bytes())
    (output / 'SHA256SUMS').write_text(''.join(
        hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
        for p in sorted(output.iterdir()) if p.suffix in ('.apk', '.apks')))
    print(f'Built and verified {len(names)} APK(s) in {output}')
    print('Keep the signing key private and backed up: future updates need the same key.')

def install(args):
    folder = args.output.resolve()
    report = json.loads((folder / 'build-report.json').read_text())
    paths = []
    for file in report['files']:
        if PurePosixPath(file['name']).name != file['name']: raise ValueError('Unsafe manifest path')
        path = folder / file['name']; data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != file['outputSHA256']: raise ValueError('APK hash mismatch')
        if verify_apk(data) != report['certificateSHA256']: raise ValueError('Certificate mismatch')
        paths.append(str(path))
    adb(['install-multiple', '-r'] + paths, args.serial)
    if args.configure:
        # Explicit opt-in: broad storage permission, battery exemption, old-server interruption.
        adb(['shell', 'am', 'force-stop', ORIGINAL], args.serial)
        adb(['shell', 'cmd', 'appops', 'set', PATCHED, 'MANAGE_EXTERNAL_STORAGE', 'allow'], args.serial)
        adb(['shell', 'dumpsys', 'deviceidle', 'whitelist', '+' + PATCHED], args.serial)
        adb(['shell', 'am', 'start', '-n', PATCHED + '/com.plexapp.mediaserver.ui.main.MainActivity'], args.serial)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=VERSION)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('build')
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument('--input', type=Path, help='APK, APKM/APKS archive, or directory of APK splits')
    source.add_argument('--from-device', action='store_true', help='Read the installed original package with ADB')
    p.add_argument('--serial', help='ADB device selector')
    p.add_argument('--output', type=Path, default=Path('build'))
    p.add_argument('--keys', type=Path, default=Path('keys'))
    p.set_defaults(func=build)
    p = commands.add_parser('install')
    p.add_argument('--output', type=Path, default=Path('build'))
    p.add_argument('--serial')
    p.add_argument('--configure', action='store_true', help='Also stop original Plex, grant All files access, exempt from Doze, and launch')
    p.set_defaults(func=install)
    p = commands.add_parser('verify')
    p.add_argument('apk', type=Path)
    p.set_defaults(func=lambda a: print('Verified; certificate SHA256:', verify_apk(a.apk.read_bytes())))
    args = parser.parse_args()
    try: args.func(args)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile, subprocess.CalledProcessError) as e:
        parser.exit(1, f'Error: {e}\n')

if __name__ == '__main__': main()
