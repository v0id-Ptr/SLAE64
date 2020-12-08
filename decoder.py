#!/usr/bin/python

import sys

shellcode = ''

if (len(sys.argv) > 1):
    arg = sys.argv[1].replace('\\x','')
    for i in xrange(0, len(arg), 2):
        x = chr(int(arg[i:i+2],16))
        shellcode += x
else:
    print "Wrong number of arguments"
    quit()

if (len(sys.argv) > 2) :
    code = int(sys.argv[2],16)
else:
    code=0xAA

original=''
encoded1=''
encoded2=''

print '\nEncoding shellcode with 0x%02x/LASTCHAR XOR ...\n' %code
for x in bytearray(shellcode) :

    original += '\\x%02x' % x

    y = x ^ code
    encoded1 += '\\x'
    encoded1 += '%02x' % y

    encoded2 += '0x'
    encoded2 += '%02x,' % y

    code = x

print 'Original:\n' + original + '\n'
print 'Encoded:\n' + encoded1 + '\n'
print 'Bytearray:\n' + encoded2 + '\n'

print 'Shellcode size: %d\n' % len(bytearray(shellcode))
