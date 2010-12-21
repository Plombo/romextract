#!/bin/sh
# A very simple shell script to build the necessary software for ROM extraction.
# Author: Bryan Cain
# Date: December 20, 2010

mkdir -p bin

fail() {
	echo "Build error"
	exit 1
}

cc src/u8it.c -obin/u8it || fail
cc src/ccfextract.c -obin/ccfextract -lz || fail
cc src/wadunpacker.c src/bn.c src/ec.c src/tools.c -lcrypto -obin/wadunpacker || fail
cc src/romc.c -obin/romc || fail
cp src/nes_rom_extract.py bin/nes_rom_extract && chmod +x bin/nes_rom_extract || fail
echo "Done!"

