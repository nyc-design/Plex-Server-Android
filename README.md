# Plex Android compatibility patcher

Build a separate, locally signed Plex Media Server app that avoids an OpenSSL
library-name collision on some non-SHIELD Android devices.

**Tested:** Plex Media Server `1.43.4.10903 (smb)`, ARM64, Android 15 on a REDMAGIC
Astra. Video playback was verified in the local Plex web player and an iPhone
Plex client. Other devices and versions are **not verified**. This is an unofficial
compatibility experiment, not a generally supported Android server port.

## What this fixes

The server can index titles while its separate scanner and transcoder fail at
startup. On the tested device, starting those components with Plex's library
search path produced:

```text
cannot locate symbol "BIO_flush" referenced by "/system_ext/lib64/libvendorutils.so"
```

Plex ships an OpenSSL `libcrypto.so`; the device's Android libraries expect a
different library with that same name. The patch changes native ELF `DT_NEEDED`
and `DT_SONAME` strings, without changing their lengths:

| Original name | Patched name |
| --- | --- |
| `libcrypto.so` | `libplexcr.so` |
| `libssl.so` | `libpsl.so` |

The app package changes from `com.plexapp.mediaserver.smb` to
`com.plexapp.mediaserver.mod`. Manifest/resource references and the explicit
external-data path in DEX are updated; DEX integrity fields are recalculated.
Java class names remain unchanged. APKs are aligned, signed with a local RSA
key using APK Signature Scheme v2, and verified after building. Original license
notices are retained. The original app and its server database remain separate.

This does not repair damaged media, add NVIDIA hardware to other devices,
bypass Plex accounts or paid features, or guarantee transcoding performance.

## Use a release

A ready-to-install release consists of an **APK set**, because this Plex version
is distributed as a base APK plus configuration splits. A base APK alone is not
a complete installation.

Download the release's installation ZIP, extract it, and install its four APKs:

```sh
adb install-multiple -r base.apk split_config.arm64_v8a.apk split_config.en.apk split_config.xhdpi.apk
```

Alternatively, the `.apks` ZIP contains the same APKs for a compatible split-APK
installer. Use a trusted installer that supports APK Signature Scheme v2. The
release APKs are signed by this project's private build key, **not Plex**.

Then follow [Configure the device](#configure-the-device). Avoid launching both
servers at once: they use the same port. Both app icons currently have Plex's
original label; the package ID distinguishes the patched version.

## Build your own

Requirements: Python 3.11+, `pip`, and optionally Android platform-tools (`adb`).
All APK processing happens on your computer; no APK, account token, or device
data is uploaded. Python dependency installation requires internet access.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, activate with `.venv\Scripts\activate` instead.

### From an installed original server

Enable Android debugging and authorize your computer, then:

```sh
python plex_patch.py build --from-device --output build --keys keys
```

This reads only the installed package's APK files. It does not copy Plex's
database, preferences, tokens, libraries, or user media. If multiple devices
are connected, specify `--serial DEVICE`.

### From a download

Supply an original ARM64 Plex Media Server APKM/APKS archive, a standalone APK,
or a directory containing a complete original APK set:

```sh
python plex_patch.py build --input original.apkm --output build --keys keys
```

Obtain input software from a source you trust. This tool records input SHA-256
hashes but does not establish that the original APK publisher is authentic.
Only the original SHIELD server package and ARM64 native code are accepted.
Use a new, empty output directory for each build. Some other APK bundle formats
or future app releases may need additional handling.

The output includes signed APKs, `plex-android-compat.apks`, `SHA256SUMS`, and
`build-report.json`. The report contains hashes and patch operations, not local
paths, account information, or device identifiers.

**Back up `keys/` privately.** Android requires the same signing key for future
updates. Losing it means a future differently signed installation cannot
replace the existing patched app while preserving its data. Never commit keys
or paste them into an issue. With the same inputs, key/certificate, Python
dependencies, and compression implementation, APK builds are deterministic.
An independently generated key produces different APK hashes by design.

## Configure the device

Install without changing permissions or stopping another app:

```sh
python plex_patch.py install --output build
```

For a one-command initial setup, **explicitly opt in**:

```sh
python plex_patch.py install --output build --configure
```

`--configure` also:

1. Stops the original Plex server, preserving its app and data.
2. Grants the patched server **All files access** to shared storage and attached media.
3. Exempts the patched server from Android Doze battery optimization.
4. Launches the patched server's setup screen.

These settings allow broad storage access and can increase battery consumption.
You can instead grant them through Android Settings. Vendor-specific background
restrictions may need separate attention.

Sign in normally, then open `http://DEVICE_IP:32400/web` and configure your
libraries. For removable storage, use the actual mounted path, for example
`/storage/CARD-ID/Media/TV Shows`. `/storage/emulated/0` is internal storage.
The patched app creates a separate server, so add your libraries again.

## Offline and screen-locked use

Cross-device playback still needs a local network. A tablet hotspot can provide
that network without internet. Sign in to every client and play representative
files while online first; Plex may need to fetch codecs or connection details.

1. Disable hotspot auto-off, if the device offers that setting.
2. Connect the client to the tablet's password-protected hotspot.
3. Disconnect the tablet from its upstream Wi-Fi/internet. On a phone client,
   use airplane mode and then re-enable Wi-Fi, so cellular cannot mask failures.
4. Read the hotspot's **Router/Gateway** address in the client's Wi-Fi details.
   Android can change this address when the hotspot restarts or networking changes.
5. Test `http://GATEWAY:32400/identity`, then `http://GATEWAY:32400/web`.
   “No Internet” in Wi-Fi settings is expected and does not itself mean no LAN.
6. Test playback, seeking, locking the server device, an extended idle period,
   and reopening the client. Test each intended client separately.

No authentication bypass is applied automatically. Cached authentication and
client discovery vary; an offline setup is not verified merely because online
playback works. A hotspot with internet access is also not an offline test.

For USB media, keep the connector mechanically secure and confirm it stays
mounted after locking. A battery exemption alone cannot guarantee USB power,
card reliability, or vendor sleep behavior. Keep ventilation around an active
server and test battery endurance before relying on it for travel. The long
offline/locked endurance test is not yet part of the verified compatibility claim.

## Roll back

Stop the patched server and launch the original:

```sh
adb shell am force-stop com.plexapp.mediaserver.mod
adb shell am start -n com.plexapp.mediaserver.smb/com.plexapp.mediaserver.ui.main.MainActivity
```

To reverse the two optional settings:

```sh
adb shell dumpsys deviceidle whitelist -com.plexapp.mediaserver.mod
adb shell cmd appops set com.plexapp.mediaserver.mod MANAGE_EXTERNAL_STORAGE default
```

Uninstalling the patched app through Settings removes its own server data.
It does not uninstall the original app. Preserve any server configuration you
need before doing so.

## Development and verification

```sh
python -m unittest discover -s tests -v
python plex_patch.py verify build/base.apk
```

Tests use synthetic ELF and ZIP fixtures, not proprietary binaries. They cover
native dependency edits, unsupported architecture rejection, APK signing and
tamper detection, ZIP path validation, alignment, and license preservation.
Android's package installer additionally verifies signatures during installation.

Reference: [Android APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2).

## Privacy and scope

The repository contains only patcher code, documentation, and synthetic tests.
Never publish ADB logs, screenshots, server databases, preferences, account
tokens, source-device dumps, or signing keys. Release files are built from app
packages, not backups of configured devices.

The MIT license applies only to the patcher source. Plex and bundled third-party
components retain their own licenses and notices. This project is not affiliated
with or endorsed by Plex, NVIDIA, or REDMAGIC.
