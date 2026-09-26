import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
import plex_patch as patch
from elftools.elf.elffile import ELFFile

def elf_fixture():
    strings = b'\0libcrypto.so\0libssl.so\0libdemo.so\0'
    # Obtain offsets from actual strings instead of assuming their lengths.
    dynamic = b''.join(struct.pack('<qQ', tag, value) for tag, value in
                       [(1, strings.index(b'libcrypto')), (1, strings.index(b'libssl')),
                        (14, strings.index(b'libdemo')), (0, 0)])
    names = b'\0.dynstr\0.dynamic\0.shstrtab\0'
    body = strings + dynamic + names
    shoff = 64 + len(body)
    ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack('<16sHHIQQQIHHHHHH', ident, 3, 183, 1, 0, 0, shoff, 0,
                         64, 0, 0, 64, 4, 3)
    sections = bytes(64)
    sections += struct.pack('<IIQQQQIIQQ', 1, 3, 0, 0, 64, len(strings), 0, 0, 1, 0)
    sections += struct.pack('<IIQQQQIIQQ', 9, 6, 0, 0, 64 + len(strings), len(dynamic), 1, 0, 8, 16)
    sections += struct.pack('<IIQQQQIIQQ', 18, 3, 0, 0, 64 + len(strings) + len(dynamic), len(names), 0, 0, 1, 0)
    return header + body + sections

class PatcherTests(unittest.TestCase):
    def test_crypto_dependencies_only(self):
        original = elf_fixture()
        result, edits = patch.patch_elf(original)
        self.assertEqual(len(original), len(result))
        self.assertEqual(len(edits), 2)
        elf = ELFFile(io.BytesIO(result))
        needed = [t.needed for t in elf.get_section_by_name('.dynamic').iter_tags()
                  if t.entry.d_tag == 'DT_NEEDED']
        self.assertEqual(needed, ['libplexcr.so', 'libpsl.so'])
        self.assertIn(b'libdemo.so\0', result)

    def test_wrong_architecture_rejected(self):
        data = bytearray(elf_fixture())
        struct.pack_into('<H', data, 18, 62)
        with self.assertRaisesRegex(ValueError, 'arm64'): patch.patch_elf(data)

    def test_signature_and_tampering(self):
        with tempfile.TemporaryDirectory() as t:
            key, cert = patch.load_identity(Path(t))
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as z: z.writestr('example.txt', b'hello' * 300000)
            signed = patch.sign_apk(buf.getvalue(), key, cert)
            self.assertEqual(patch.verify_apk(signed), patch.hashlib.sha256(cert).hexdigest())
            changed = bytearray(signed); changed[100] ^= 1
            with self.assertRaisesRegex(ValueError, 'digest mismatch'): patch.verify_apk(changed)
            key2, cert2 = patch.load_identity(Path(t))
            self.assertEqual(cert, cert2)
            self.assertEqual(signed, patch.sign_apk(buf.getvalue(), key2, cert2))

    def test_path_traversal_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z: z.writestr('../bad.apk', b'bad')
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as z:
            with self.assertRaisesRegex(ValueError, 'Unsafe'): patch.validate_archive(z)

    def test_rebuild_preserves_licenses_and_removes_old_signatures(self):
        with tempfile.TemporaryDirectory() as t:
            key, cert = patch.load_identity(Path(t))
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as z:
                z.writestr('AndroidManifest.xml', patch.ORIGINAL.encode())
                z.writestr('META-INF/LICENSE', b'keep this license')
                z.writestr('META-INF/CERT.RSA', b'old signature')
                z.writestr('lib/arm64-v8a/libdemo.so', elf_fixture())
            result, edits = patch.rebuild_apk(buf.getvalue(), key, cert)
            self.assertTrue(edits)
            with zipfile.ZipFile(io.BytesIO(result)) as z:
                self.assertEqual(z.read('META-INF/LICENSE'), b'keep this license')
                self.assertNotIn('META-INF/CERT.RSA', z.namelist())
                self.assertEqual(z.read('AndroidManifest.xml'), patch.PATCHED.encode())
                info = z.getinfo('lib/arm64-v8a/libdemo.so')
                data_offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
                self.assertEqual(data_offset % 16384, 0)

if __name__ == '__main__': unittest.main()
