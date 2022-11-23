import veradecrypthor_utils
import argparse
from cryptography.hazmat.primitives import hashes


def decrypt_header(ciphertext, key):
    tweak = veradecrypthor_utils.convert_to_16_byte_little_endian(0)

    plaintext = veradecrypthor_utils.decrypt_aes_with_tweak(
        ciphertext=ciphertext,
        key=key, tweak=tweak)
    return_val = None
    if plaintext[0:4] == b"VERA":
        return_val = plaintext
    return return_val


def print_container_header_plaintext(plaintext):
    print("""--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    |   Salt                                                | {0}
    |   VERA (V=56, E=45, R=52, A=41)                       | {1}
    |   Volume header format version                        | {2}
    |   Minimum program version                             | {3}
    |   CRC-32 checksum of the (decrypted) bytes 256-511    | {4}
    |   Reserved (must contain zeroes)                      | {5}
    |   Size of hidden volume (0 in non-hidden volumes)     | {6}
    |   Size of volume                                      | {7}
    |   Byte offset of the start of the master key scope    | {8}
    |   Size of the enc. area within the master key scope   | {9}
    |   Flag bits*                                          | {10}
    |   Sector size (in bytes)                              | {11}
    |   Reserved (must contain zeroes)                      | {12}
    |   CRC-32 checksum of the (decrypted) bytes 64-251     | {13}
    |   Concatenated primary and secondary master keys**    | {14}
    --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    *  Flag bits (bit 0 set: system encryption; bit 1 set: non-system
       in-place-encrypted/decrypted volume; bits 2–31 are reserved)

    ** Multiple concatenated master keys are stored here when the volume is
       encrypted using a cascade of ciphers (secondary master keys are used for
       XTS mode).
    --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------""".format(
        hex_salt, plaintext.hex()[0:8], plaintext.hex()[8:12],
        plaintext.hex()[12:16],
        plaintext.hex()[16:24], plaintext.hex()[24:56],
        plaintext.hex()[56:72],
        plaintext.hex()[72:88],
        plaintext.hex()[88:104], plaintext.hex()[104:120],
        plaintext.hex()[120:128],
        plaintext.hex()[128:136], plaintext.hex()[136:376],
        plaintext.hex()[376:384], plaintext.hex()[384:1024]))


if __name__ == '__main__':
    print(veradecrypthor_utils.LOGO)
    parser = argparse.ArgumentParser()

    # arguments
    parser.add_argument("i", help="filepath to container file")
    parser.add_argument("p", help="password for the given container file")
    parser.add_argument("c",
                        help="\"outer\" for regular volume or \"hidden\" for hidden volume")

    args = parser.parse_args()

    #####################################################################
    ###              Assingning arguments to variables                ###
    #####################################################################
    password = bytes(args.p, "latin-1")  # -p --password
    filename = args.i  # -i --input
    container = args.c  # option for inner and outer volume
    #####################################################################
    ###   Extract header and assign variables for further execution   ###
    #####################################################################
    if container == "hidden":
        byte_header = veradecrypthor_utils.extract_data(filename, offset=65536,
                                                        end=131072)
    else:
        byte_header = veradecrypthor_utils.extract_data(filename, offset=0,
                                                        end=65536)
    # when inner volume change offset
    # divide byte_header
    byte_salt = byte_header[:64]
    byte_enc_header_part = byte_header[64:]

    # hex data for output
    hex_header = byte_header.hex()
    hex_salt = hex_header[:128]
    hex_enc_header_part = hex_header[128:]

    #####################################################################
    ###        Derive key and print decrypted container header        ###
    #####################################################################

    key = veradecrypthor_utils.derive_passwort(algorithm=hashes.SHA512,
                                               length=64,
                                               salt=byte_salt,
                                               iterations=500_000,
                                               # from VeraCrypt docs
                                               password=password)

    print_container_header_plaintext(decrypt_header(byte_enc_header_part, key))

exit(0)
