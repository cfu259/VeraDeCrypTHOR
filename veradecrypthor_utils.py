from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac

LOGO = """ __      __                _____          _____                   _______  _    _   ____   _____  
 \ \    / /               |  __ \        / ____|                 |__   __|| |  | | / __ \ |  __ \ 
  \ \  / /___  _ __  __ _ | |  | |  ___ | |      _ __  _   _  _ __  | |   | |__| || |  | || |__) |
   \ \/ // _ \| '__|/ _` || |  | | / _ \| |     | '__|| | | || '_ \ | |   |  __  || |  | ||  _  / 
    \  /|  __/| |  | (_| || |__| ||  __/| |____ | |   | |_| || |_) || |   | |  | || |__| || | \ \ 
     \/  \___||_|   \__,_||_____/  \___| \_____||_|    \__, || .__/ |_|   |_|  |_| \____/ |_|  \_\\
                                                        __/ || |                                  
                                                       |___/ |_|"""


def extract_data(filepath, offset=0, end=None) -> bytes:
    container_raw = ""
    with open(filepath, "rb") as file:
        container_raw = file.read()
    if offset == 0:
        if end != None:
            container_raw = container_raw[0:end]
        else:
            pass  # do nothing
    else:
        if end != None:
            container_raw = container_raw[offset:end]
        else:
            container_raw = container_raw[offset:]
    return container_raw


def convert_to_16_byte_little_endian(value):
    if type(value) == int:
        value = hex(value).rsplit('x')[1]  # handles integer values
    if value.startswith("0x"):
        value = value.rsplit('x')[1]  # 0xcoffee --> coffee

    value = '0' * (32 - len(value)) + value  # creates 16 byte value
    # make little endian value
    return bytes.fromhex(
        "".join(reversed([value[i:i + 2] for i in range(0, len(value), 2)])))


def convert_to_16_byte_big_endian(value):
    if type(value) == int:
        value = hex(value).rsplit('x')[1]  # handles integer values
    if value.startswith("0x"):
        value = value.rsplit('x')[1]  # 0xcoffee --> coffee
    return bytes.fromhex(
        '0' * (32 - len(value)) + value)  # creates 16 byte value


def xor(val_a, val_b) -> bytes:
    return bytes.fromhex(val_a) ^ bytes.fromhex(val_b)


def derive_passwort(algorithm, length, salt, iterations, password) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=algorithm,
        length=length,
        salt=salt,
        iterations=iterations
    )
    return kdf.derive(password)


def decrypt_aes_with_tweak(ciphertext, key, tweak):
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
