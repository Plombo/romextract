#!/usr/bin/env python
# Extracts an NES ROM from a 00000001.app file extracted from an NES Virtual Console WAD.

import sys

if __name__ == '__main__':
	if len(sys.argv) != 3:
		sys.exit('Usage: %s input.app output.nes' % sys.argv[0])
	f = open(sys.argv[1], 'rb')
	f2 = open(sys.argv[2], 'wb')
	romoffset = 0
	while True:
		buf = f.read(8192)
		if buf.find('NES\x1a') >= 0:
			romoffset += buf.find('NES\x1a')
			break
		elif len(buf) != 8192:
			f.close()
			sys.exit('No NES rom found in %s' % sys.argv[1])
		else: romoffset += 8192
	
	# NES ROM found; calculate size and extract it
	print 'NES ROM found at offset %i' % romoffset
	f.seek(romoffset)
	print [f.read(4)] # first 4 bytes should be 'NES\x1a'
	size = 16 + 128 # 16-byte header, 128-byte title data (footer)
	size += 16 * 1024 * ord(f.read(1)) # next byte: number of PRG banks, 16KB each
	size += 8 * 1024 * ord(f.read(1)) # next byte: number of CHR banks, 8KB each
	size = 2**30
	f.seek(romoffset)
	print 'ROM size: %i bytes' % size
	f2 = open(sys.argv[2], 'wb')
	f2.write(f.read(size))
	f2.close()
	f.close()
	print 'Successfully created NES ROM file %s' % sys.argv[2]
	sys.exit(0)
	
