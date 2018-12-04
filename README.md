# CBC Mode Padding Oracle Attack

```
❯ python cbc_padding_oracle_attack.py
Algorithm: Crypto.Cipher.AES
Plain Text: b'THIS IS A SUPER SECRET MESSAGE'
Cipher Text: b'\xae_\xc85t\x14\xf9\xdf\xcf\x18\xe3\xd2\x8e\xdej1\x99`\xd19\x14B6]r\x11\r\x0ccF\x1as\x04 \xa8tz[w\xcc\x9c\x94\xc3\xbf\x90\xbb\xf5\xeb'
---- Start Attack ----
Byte Decrypted: 0x02
Byte Decrypted: 0x02
Byte Decrypted: 0x45
Byte Decrypted: 0x47
Byte Decrypted: 0x41
Byte Decrypted: 0x53
Byte Decrypted: 0x53
Byte Decrypted: 0x45
Byte Decrypted: 0x4d
Byte Decrypted: 0x20
Byte Decrypted: 0x54
Byte Decrypted: 0x45
Byte Decrypted: 0x52
Byte Decrypted: 0x43
Byte Decrypted: 0x45
Byte Decrypted: 0x53
Byte Decrypted: 0x20
Byte Decrypted: 0x52
Byte Decrypted: 0x45
Byte Decrypted: 0x50
Byte Decrypted: 0x55
Byte Decrypted: 0x53
Byte Decrypted: 0x20
Byte Decrypted: 0x41
Byte Decrypted: 0x20
Byte Decrypted: 0x53
Byte Decrypted: 0x49
Byte Decrypted: 0x20
Byte Decrypted: 0x53
Byte Decrypted: 0x49
Byte Decrypted: 0x48
Byte Decrypted: 0x54
Hacked Plain Text: THIS IS A SUPER SECRET MESSAGE
```
