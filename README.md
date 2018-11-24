PyNUSD
========
This is a Wii NUS downloader written in Python 3(.6). It uses my own [WADGEN](WADGEN.py), completely written from scratch to create WADs from CDN content. PyNUSD can even create tickets from encrypted title keys.
It uses the `requests` module, so you'll need to install it with e.g. pip. Based on [3DS-NUSD](https://github.com/WiiDatabase/3DS-NUSD).

"WADGEN" can create WADs from cetk + tmd + contents completely in Python. It can also unpack a WAD to its CDN contents and decrypt them!

## Usage
```
usage: PyNUSD.py [-h] [--nopack] [--deletecontents] [--key ENCRYPTED_KEY]
                 [--onlyticket]
                 titleid [titleversion]

positional arguments:
  titleid              Title ID
  titleversion         Title version (default: Latest)

optional arguments:
  -h, --help           show this help message and exit
  --nopack             Do not generate WAD.
  --deletecontents     Do not keep contents.
  --key ENCRYPTED_KEY  Encrypted title key for Ticket generation.
  --onlyticket         Only create the ticket, don't store anything.
```

## Notes
* Creates valid WADs which are nearly the same as the one from Discs (only missing the footer)
* Doesn't modify the original TMD and contents like NUSD
* WADGEN can be used independently
  
## TODO
- [ ] More Error handling and retrying
- [ ] Improve error handling in WADGEN, especially for certificates and too short tmds/tickets
- [ ] Support for decrypting & SHA1 verify
- [ ] uselocal parameter (needs SHA1 verifying)
- [ ] GUI
  
## Credits
* Daeken for original Struct.py
* [grp](https://github.com/grp) for Wii.py)

## Screenshots
![Screenshot](screenshot.png?raw=true)

![Screenshot2](screenshot2.png?raw=true)