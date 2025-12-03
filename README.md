# PY_COFFLoader
Pure Python ctypes COFFLoader implementation without reflection.

Fully converted from https://github.com/trustedsec/CS_COFFLoader
##

Usage example:
```bash
git clone https://github.com/zulfi0/PY_COFFLoader
cd PY_COFFLoader
python.exe CoffLoader.py -file .\whoami.x64.o
```
Executing whoami.o:
<img width="1728" height="786" alt="image" src="https://github.com/user-attachments/assets/93f1cc74-2215-4ad9-b461-590011b59854" />


Available options:
```bash
 python.exe .\CoffLoader.py -h
usage: CoffLoader.py [-h] [-args ARGS] -file FILE [-func FUNC]

Python COFFLoader

options:
  -h, --help  show this help message and exit
  -args ARGS  BOF arguments. default "00" (otherwise VirtualAlloc will throw an error)
  -file FILE  BOF file to execute
  -func FUNC  BOF Function name. default "go"
```

##
Resources:

https://trustedsec.com/blog/coffloader-building-your-own-in-memory-loader-or-how-to-run-bofs

https://github.com/zimnyaa/inmembof.py

https://github.com/trustedsec/CS_COFFLoader
