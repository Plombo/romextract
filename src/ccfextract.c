/**
 * Extractor for CCF archive format used in Sega Genesis Virtual Console WADs.
 * Author: Bryan Cain
 * Date: August 14, 2010
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __WIN32__
#include <windows.h>
#define DIREXISTS(x) (SetCurrentDirectory(x) != 0)
#define MKDIR(x) mkdir(x)
#else
#include <unistd.h>
#define DIREXISTS(x) (chdir(x) >= 0)
#define MKDIR(x) mkdir(x, 0777)
#endif

#pragma pack(1)
#define MIN(x,y) (((x)>(y))?(y):(x))
#define assert_msg(x, str) if(!(x)) { fprintf(stderr, "%s\n", str); return false; }

typedef struct {
	char		name[20]; // name, truncated or 0-padded to 20 bytes
	uint32_t 	offset; // multiply by 32 to get the real offset
	uint32_t	csize; // compressed size
	uint32_t	usize; // uncompressed size
} __attribute__((packed)) direntry;

bool myfread()
{
	
}

#define CHUNK 16384

/* Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files.
   
   Modified from the inf function in zpipe.c, which is in the public 
   domain. The original is available at: http://zlib.net/zpipe.c  */
int inf(FILE *source, FILE *dest, int csize)
{
    int ret;
    unsigned have;
    z_stream strm;
	int bytes_to_read, bytes_remaining = csize;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return ret;

    /* decompress until deflate stream ends or end of file */
    do {
        bytes_to_read = MIN(bytes_remaining, CHUNK);
		if(bytes_to_read == 0) break;
		bytes_remaining -= bytes_to_read;
		
		strm.avail_in = fread(in, 1, bytes_to_read, source);
        if (ferror(source)) {
            (void)inflateEnd(&strm);
            return Z_ERRNO;
        }
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            if(ret == Z_STREAM_ERROR) { printf("Zlib state clobbered?\n"); exit(0); }
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(&strm);
                return ret;
            }
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)inflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    (void)inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

// No error checking!  Assumes that program is runnning on a little-endian system.
bool ccf_extract(char* filename, char* outputdir)
{
	int i, bytes_remaining, bytes_to_read;
	uint32_t numfiles;
	char realname[21];
	direntry* fileinfo;
	FILE* fp = fopen(filename, "rb"), *out;
	char buf[8192];
	
	fseek(fp, 0x14, SEEK_SET);
	fread(&numfiles, 4, 1, fp);
	fileinfo = malloc(numfiles * sizeof(direntry));
	printf("%i files\n", numfiles);
	
	fseek(fp, 0x20, SEEK_SET);
	fread(fileinfo, sizeof(direntry), numfiles, fp);
	
	if(!DIREXISTS(outputdir)) { MKDIR(outputdir); }
	chdir(outputdir);
	
	for(i=0; i<numfiles; i++)
	{
		strncpy(realname, fileinfo[i].name, 20);
		printf("%s: offset=0x%0x, csize=0x%0x, usize=0x%0x\n", realname, 32*fileinfo[i].offset, fileinfo[i].csize, fileinfo[i].usize);
		fseek(fp, 32*fileinfo[i].offset, SEEK_SET);
		out = fopen(realname, "wb");
		
		if(fileinfo[i].csize != fileinfo[i].usize) // zlib-compressed
		{
			inf(fp, out, fileinfo[i].csize);
		}
		else // uncompressed
		{
			bytes_remaining = fileinfo[i].csize;
			while(bytes_remaining)
			{
				bytes_to_read = MIN(8192, bytes_remaining);
				fread(buf, 1, bytes_to_read, fp);
				fwrite(buf, 1, bytes_to_read, out);
				bytes_remaining -= bytes_to_read;
			}
		}
		
		fclose(out);
	}
	
	fclose(fp);
	free(fileinfo);
}

int main(int argc, char** argv)
{
	if(argc != 3)
	{
		printf("Usage: %s archive.ccf outputdir\n", argv[0]);
		exit(1);
	}
	
	printf("%i args\n", argc);
	ccf_extract(argv[1], argv[2]);
	
	return 0;
}

