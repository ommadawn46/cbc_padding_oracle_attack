from Crypto.Cipher import DES, Blowfish, AES
from struct import pack
import random

#ALGORITHM = DES
#ALGORITHM = Blowfish
ALGORITHM = AES

KEY_SIZE = ALGORITHM.key_size
BLOCK_SIZE = ALGORITHM.block_size

def random_bytes(n):
    if type(n) is not int:
        n = max(n)
    return bytes([random.randint(0, 255) for _ in range(n)])


# ---- サーバ側 ----

SECRET_KEY = random_bytes(KEY_SIZE)

def pad(message):
    # PKCS #5 (or #7) パディングを付与
    pad_len = BLOCK_SIZE - len(message) % BLOCK_SIZE
    padding = [pad_len]*pad_len
    padding = pack('b'*pad_len, *padding)
    return message + padding

def unpad(message):
    # PKCS #5 (or #7) パディングを取り除く（規格に適合しない文字列は例外で落とす）
    pad_len = message[-1]
    if not 1 <= pad_len <= BLOCK_SIZE:
        raise
    for i in range(pad_len):
        if message[-i-1] != pad_len:
            raise
    return message[:-pad_len]

def encrypt(message):
    iv = random_bytes(BLOCK_SIZE)
    cipher = ALGORITHM.new(SECRET_KEY, ALGORITHM.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(message))

def decrypt(cipher_text):
    iv = cipher_text[:BLOCK_SIZE]
    cipher = ALGORITHM.new(SECRET_KEY, ALGORITHM.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_text[BLOCK_SIZE:]))

def padding_oracle(cipher_text):
    # 復号の成否を教えてくれるオラクル
    # 復号結果がPKCS #5 (or #7)に適合する平文になったかどうかを知るために使用できる
    try:
        decrypt(cipher_text)
        return True
    except:
        return False


# ---- 攻撃者側 ----

def attack(cipher_text):
    # 攻撃コード
    # C: 元の暗号文, C': 改ざんした暗号文, P: 平文

    # Cをブロックごとに分割
    c_blocks = [cipher_text[i:i+BLOCK_SIZE] for i in range(0, len(cipher_text), BLOCK_SIZE)]

    hacked_plain_text = ''
    for block_idx in range(1, len(c_blocks)):
        c_dash = b''
        for pad_len in range(1, BLOCK_SIZE+1):
            for c_dash_b in range(256):
                # 0x0 ~ 0xff の文字を順番に入れて復号に成功する C'を探す
                new_c_dash = bytes([c_dash_b]) + c_dash
                c_dash_block = random_bytes(BLOCK_SIZE-pad_len) + new_c_dash
                c_dash_blocks = c_blocks[:-block_idx-1] + [c_dash_block] + [c_blocks[-block_idx]]

                # パディングオラクルにかける
                if padding_oracle(b''.join(c_dash_blocks)):
                    # 復号成功
                    # P = pad_len ^ C ^ C'
                    c_block = c_blocks[-block_idx-1]
                    p = pad_len ^ c_block[-pad_len] ^ c_dash_b
                    hacked_plain_text += chr(p)
                    print('Byte Decrypted: 0x%02x' % p)

                    # 次のパディングに向けて値を調整する（例. \x02\x02 → \x03\x03）
                    c_dash = bytes([
                        byte ^ pad_len ^ (pad_len+1) for byte in new_c_dash
                    ])
                    break

    # 文字順が逆さになるのでreverse
    return hacked_plain_text[::-1]


if __name__ == '__main__':
    print("Algorithm:", ALGORITHM.__name__)

    plain_text = b'THIS IS A SUPER SECRET MESSAGE'
    print("Plain Text:", plain_text)

    cipher_text = encrypt(plain_text)
    print("Cipher Text:", cipher_text)

    print("---- Start Attack ----")
    hacked_plain_text = attack(cipher_text)
    print("Hacked Plain Text:", hacked_plain_text)
