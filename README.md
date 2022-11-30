# VeraDeCrypTHOR

This program was created as part of my bachelor thesis "Forensic Analysis of Crypto Containers".

For this work VeraCrypt containers of version 1.25.9 were examined.

The VeraDeCrypTHOR is a proof-of-concept solution and is used to verify the master keys for the data area. It was shown that the keys stored in the header for the data area match keys extracted from RAM.

## Hints for use
1. You need at least Python 3.10 and pip
2. Download repo
2. Open shell and go to downloaded directory `$ cd to_the_location_of_the_repo`
3. Install requirements `$ python -m pip install -r requirements.txt`
3. `$ python ./decrypt_container_header.py filepath_to_container password [inner, outer]`

### Specifications
Currently the VeraDeCrypTHOR only works for Container with the following properties:
- Encryption AES256 in XTS mode.
- PBKDF2 uses HMAC-SHA512 as PRF
- No individual PIM is supported, so the default specification from the VeraCrypt documentation for HMAC-SHA512 is used<br>
  500 000 iterations

## Change key script
Use change_key.py to change the hard-coded data keys. You have to replace the VolumeHeader.cpp in the VeraCrypt program files (i. e. VeraCrypt/src) with the newly created file.

Via Console:<br>
- `$ python ./change_key.py <aes_key> <xts_key>`
- `[cp, mv] VolumeHeader.cpp VeraCrypt/src/VolumeHeader.cpp` (yes, replace file in folder)

Instead of downloading the VeraCrypt Software from its [origin](https://github.com/veracrypt/VeraCrypt) you can use [this repo (cfu259/VeraCracker)](https://github.com/cfu259/VeraCracker).