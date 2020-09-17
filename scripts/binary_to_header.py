#!/usr/bin/env python
import sys, os

if len(sys.argv) < 2:
    print "Usage: %s FILENAME [VARNAME]" % sys.argv[0]
    sys.exit(1)

filename = sys.argv[1]
filesize = os.path.getsize(filename)

if len(sys.argv) > 2: varname = sys.argv[2]
else:                 varname = filename.replace('.', '_')

print "unsigned char %s[%d] = {" % (varname, filesize),
with open(filename, 'rb') as f:
    byte = f.read(1)
    while byte != "":
        sys.stdout.write(str(ord(byte)) + ',')
        byte = f.read(1)
print "};"
