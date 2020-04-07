#!/bin/sh

# For finding the permissions
apktool d terrortime.apk
echo "[+] Here are the permissions: "
grep -r "android.permission" terrortime/AndroidManifest.xml

# For finding the cert info
binwalk -o=0xB9F36A --dd=".*" terrortime.apk
echo "[+] Here is the common name of the certificate: "
openssl x509 -in _terrortime.apk.extracted/B9F36A -text -noout -inform DER | grep "CN"
echo "[+] Here is the SHA256 sum of the certificate: "
sha256sum _terrortime.apk.extracted/B9F36A
