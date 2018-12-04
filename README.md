PyNUSD
========
This is a **Wii and DSi NUS downloader** written in Python 3(.6). It uses my own [WADGEN](WADGEN.py), completely written from scratch to create WADs from CDN content. PyNUSD can even create tickets from encrypted title keys.

It uses the `requests` module, so you'll need to install it with e.g. pip. Based on [3DS-NUSD](https://github.com/WiiDatabase/3DS-NUSD).

"**WADGEN**" can create WADs from cetk + tmd + contents completely in Python. It can also unpack a WAD to its CDN contents, decrypt them, show information and much more!

## Features
### PyNUSD
* Downloads Wii, vWii and DSi titles from the **N**intendo **U**pdate **S**erver
* Can decrypt contents and pack them as valid WAD
* Also accepts encrypted title keys
* Verifies existing files via SHA1 sum (only for those with ticket)
* Supports CDN mirrors through the `--base` parameter
* Uses my own WADGEN, completely tested, verified and written from scratch

### WADGEN
* Can be used as independent library
* Creates valid WADs which are nearly the same as the one from Discs (only missing the footer)
* Doesn't modify the original TMD and contents like NUSD
* Can handle DSi titles (but not pack them obviously)
* Verifies Signature (place root-key in the same directory)
* Can fix WADs with wrong common key index and wrong certificate chain

## Usage
```
usage: PyNUSD.py [-h] [--nopack] [--decrypt] [--deletecontents] [--nolocaluse]
                 [--key ENCRYPTED_KEY] [--onlyticket] [--cdn]
                 [--base BASE_URL]
                 titleid [titleversion]

positional arguments:
  titleid              Title ID
  titleversion         Title version (default: Latest)

optional arguments:
  -h, --help           show this help message and exit
  --nopack             Do not generate WAD
  --decrypt            Create decrypted contents (*.app)
  --deletecontents     Do not keep contents
  --nolocaluse         Don't use local files (SHA1 sum verifying)
  --key ENCRYPTED_KEY  Encrypted title key for Ticket generation
  --onlyticket         Only create the ticket, don't store anything
  --cdn                Store contents like on CDN (without version directory)
  --base BASE_URL      Base URL for CDN download
```
  
## TODO
- [ ] More Error handling and retrying
- [ ] Improve error handling in WADGEN, especially for certificates and too short tmds/tickets
- [X] Support for decrypting
- [X] SHA1 verify
- [X] uselocal parameter (needs decrypting & SHA1 verifying)
- [X] WADMaker: Support TMDs with number (e.g. `tmd.512`)
- [X] Add flag for not using version directories, just the TID (like CDN structure)
- [X] Also verify first time downloaded files
- [ ] GUI?
  
## Credits
* Daeken for original Struct.py
* [grp](https://github.com/grp) for Wii.py

## Screenshots
![Screenshot](screenshot.png?raw=true)

![Screenshot2](screenshot2.png?raw=true)