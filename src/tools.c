// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
// Modified by BFGR

#include "tools.h"

#include <stddef.h>	// to accommodate certain broken versions of openssl
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//
// basic data types
//

u8 generic_tik[676]={
	0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 82,111,111,116,45,67,65,48,48,48,48,48,48,48,49,45,88,83,48,48,
 48,48,48,48,48,51,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,123,-114,73,-63,-55,-3,49,106,-101,-108,20,-128,-106,
 -102,49,-62,0,0,1,-84,-27,-29,-114,76,104,0,0,0,0,0,1,0,1,
 74,66,68,80,-1,-1,0,0,0,0,0,0,0,0,0,0,0,86,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
 -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

u16 be16(const u8 *p)
{
	return (p[0] << 8) | p[1];
}

u32 be32(const u8 *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

u64 be64(const u8 *p)
{
	return ((u64)be32(p) << 32) | be32(p + 4);
}

u64 be34(const u8 *p)
{
	return 4 * (u64)be32(p);
}

void wbe16(u8 *p, u16 x)
{
	p[0] = x >> 8;
	p[1] = x;
}

void wbe32(u8 *p, u32 x)
{
	wbe16(p, x >> 16);
	wbe16(p + 2, x);
}

void wbe64(u8 *p, u64 x)
{
	wbe32(p, x >> 32);
	wbe32(p + 4, x);
}

//
// crypto
//

void md5(u8 *data, u32 len, u8 *hash)
{
	MD5(data, len, hash);
}

void sha(u8 *data, u32 len, u8 *hash)
{
	SHA1(data, len, hash);
}

void get_key(const char *name, u8 *key, u32 len)
{
	char path[256];
	//char *home;
	FILE *fp;

	//home = getenv("HOME");
	//if (home == 0)
	//	fatal("cannot find HOME");
	snprintf(path, sizeof path, "%s", name);

	fp = fopen(path, "rb");
	if (fp == 0)
		fatal("cannot open %s", name);
	if (fread(key, len, 1, fp) != 1)
		fatal("error reading %s", name);
	fclose(fp);
}

void aes_cbc_dec(u8 *key, u8 *iv, u8 *in, u32 len, u8 *out)
{
	AES_KEY aes_key;

	AES_set_decrypt_key(key, 128, &aes_key);
	AES_cbc_encrypt(in, out, len, &aes_key, iv, AES_DECRYPT);
}

void aes_cbc_enc(u8 *key, u8 *iv, u8 *in, u32 len, u8 *out)
{
	AES_KEY aes_key;

	AES_set_encrypt_key(key, 128, &aes_key);
	AES_cbc_encrypt(in, out, len, &aes_key, iv, AES_ENCRYPT);
}

void decrypt_title_key(u8 *tik, u8 *title_key)
{
	u8 common_key[16];
	u8 iv[16];

	get_key("common-key.bin", common_key, 16);

	memset(iv, 0, sizeof iv);
	memcpy(iv, tik + 0x01dc, 8);
	aes_cbc_dec(common_key, iv, tik + 0x01bf, 16, title_key);
}

static u8 root_key[0x204];
static u8 *get_root_key(void)
{
	get_key("root-key.bin", root_key, sizeof root_key);
	return root_key;
}

static u32 get_sig_len(u8 *sig)
{
	u32 type;

	type = be32(sig);
	switch (type - 0x10000) {
	case 0:
		return 0x240;

	case 1:
		return 0x140;

	case 2:
		return 0x80;
	}

	fprintf(stderr, "get_sig_len(): unhandled sig type %08x\n", type);
	return 0;
}

static u32 get_sub_len(u8 *sub)
{
	u32 type;

	type = be32(sub + 0x40);
	switch (type) {
	case 0:
		return 0x2c0;

	case 1:
		return 0x1c0;

	case 2:
		return 0x100;
	}

	fprintf(stderr, "get_sub_len(): unhandled sub type %08x\n", type);
	return 0;
}

int check_ec(u8 *ng, u8 *ap, u8 *sig, u8 *sig_hash)
{
	u8 ap_hash[20];
	u8 *ng_Q, *ap_R, *ap_S;
	u8 *ap_Q, *sig_R, *sig_S;

	ng_Q = ng + 0x0108;
	ap_R = ap + 0x04;
	ap_S = ap + 0x22;

	SHA1(ap + 0x80, 0x100, ap_hash);

	ap_Q = ap + 0x0108;
	sig_R = sig;
	sig_S = sig + 30;

	return check_ecdsa(ng_Q, ap_R, ap_S, ap_hash)
	       && check_ecdsa(ap_Q, sig_R, sig_S, sig_hash);
}

static int check_rsa(u8 *h, u8 *sig, u8 *key, u32 n)
{
	u8 correct[0x200];
	u8 x[0x200];
	static const u8 ber[16] = "\x00\x30\x21\x30\x09\x06\x05\x2b"
	                          "\x0e\x03\x02\x1a\x05\x00\x04\x14";

//fprintf(stderr, "n = %x\n", n);
//fprintf(stderr, "key:\n");
//hexdump(key, n);
//fprintf(stderr, "sig:\n");
//hexdump(sig, n);

	correct[0] = 0;
	correct[1] = 1;
	memset(correct + 2, 0xff, n - 38);
	memcpy(correct + n - 36, ber, 16);
	memcpy(correct + n - 20, h, 20);
//fprintf(stderr, "correct is:\n");
//hexdump(correct, n);

	bn_exp(x, sig, key, n, key + n, 4);
//fprintf(stderr, "x is:\n");
//hexdump(x, n);

	if (memcmp(correct, x, n) == 0)
		return 0;

	return -5;
}

static int check_rsa_trucha(u8 *h, u8 *sig, u8 *key, u32 n)
{
	u8 correct[0x200];
	u8 x[0x200];
	static const u8 ber[16] = "\x00\x30\x21\x30\x09\x06\x05\x2b"
			"\x0e\x03\x02\x1a\x05\x00\x04\x14";

//fprintf(stderr, "n = %x\n", n);
//fprintf(stderr, "key:\n");
//hexdump(key, n);
//fprintf(stderr, "sig:\n");
//hexdump(sig, n);

	correct[0] = 0;
	correct[1] = 1;
	memset(correct + 2, 0xff, n - 38);
	memcpy(correct + n - 36, ber, 16);
	memcpy(correct + n - 20, h, 20);
//fprintf(stderr, "correct is:\n");
//hexdump(correct, n);

	bn_exp(x, sig, key, n, key + n, 4);
//fprintf(stderr, "x is:\n");
//hexdump(x, n);

	if (strncmp(correct, x, n) == 0)
		return 0;

	return -5;
}

static int check_hash(u8 *h, u8 *sig, u8 *key)
{
	u32 type;

	type = be32(sig) - 0x10000;
	if (type != be32(key + 0x40))
		return -6;

	switch (type) {
	case 1:
		return check_rsa(h, sig + 4, key + 0x88, 0x100);
	}

	return -7;
}

static int check_hash_trucha(u8 *h, u8 *sig, u8 *key)
{
	u32 type;

	type = be32(sig) - 0x10000;
	if (type != be32(key + 0x40))
		return -6;

	switch (type) {
		case 1:
			return check_rsa_trucha(h, sig + 4, key + 0x88, 0x100);
	}

	return -7;
}

static u8 *find_cert_in_chain(u8 *sub, u8 *cert, u32 cert_len)
{
	char parent[64];
	char *child;
	u32 sig_len, sub_len;
	u8 *p;
	u8 *issuer;

	strncpy(parent, sub, sizeof parent);
	parent[sizeof parent - 1] = 0;
	child = strrchr(parent, '-');
	if (child)
		*child++ = 0;
	else {
		*parent = 0;
		child = sub;
	}

	for (p = cert; p < cert + cert_len; p += sig_len + sub_len) {
		sig_len = get_sig_len(p);
		if (sig_len == 0)
			return 0;
		issuer = p + sig_len;
		sub_len = get_sub_len(issuer);
		if (sub_len == 0)
			return 0;

		if (strcmp(parent, issuer) == 0
		    && strcmp(child, issuer + 0x44) == 0)
			return p;
	}

	return 0;
}

int check_cert_chain(u8 *data, u32 data_len, u8 *cert, u32 cert_len)
{
	u8 *sig;
	u8 *sub;
	u32 sig_len;
	u32 sub_len;
	u8 h[20];
	u8 *key_cert;
	u8 *key;
	int ret;

	sig = data;
	sig_len = get_sig_len(sig);
	if (sig_len == 0)
		return -1;
	sub = data + sig_len;
	sub_len = data_len - sig_len;
	if (sub_len == 0)
		return -2;

	for (;;) {
fprintf(stderr, ">>>>>> checking sig by %s...\n", sub);
		if (strcmp(sub, "Root") == 0) {
			key = get_root_key();
			sha(sub, sub_len, h);
			if (be32(sig) != 0x10000)
				return -8;
			return check_rsa(h, sig + 4, key, 0x200);
		}

		key_cert = find_cert_in_chain(sub, cert, cert_len);
		if (key_cert == 0)
			return -3;

		key = key_cert + get_sig_len(key_cert);

		sha(sub, sub_len, h);
		ret = check_hash(h, sig, key);
		if (ret)
			return ret;

		sig = key_cert;
		sig_len = get_sig_len(sig);
		if (sig_len == 0)
			return -4;
		sub = sig + sig_len;
		sub_len = get_sub_len(sub);
		if (sub_len == 0)
			return -5;
	}
}

int check_cert_chain_trucha(u8 *data, u32 data_len, u8 *cert, u32 cert_len)
{
	u8 *sig;
	u8 *sub;
	u32 sig_len;
	u32 sub_len;
	u8 h[20];
	u8 *key_cert;
	u8 *key;
	int ret;

	sig = data;
	sig_len = get_sig_len(sig);
	if (sig_len == 0)
		return -1;
	sub = data + sig_len;
	sub_len = data_len - sig_len;
	if (sub_len == 0)
		return -2;

	for (;;) {
fprintf(stderr, ">>>>>> checking trucha sig by %s...\n", sub);
		if (strcmp(sub, "Root") == 0) {
			key = get_root_key();
			sha(sub, sub_len, h);
			if (be32(sig) != 0x10000)
				return -8;
			return check_rsa_trucha(h, sig + 4, key, 0x200);
		}

		key_cert = find_cert_in_chain(sub, cert, cert_len);
		if (key_cert == 0)
			return -3;

		key = key_cert + get_sig_len(key_cert);

		sha(sub, sub_len, h);
		ret = check_hash_trucha(h, sig, key);
		if (ret)
			return ret;

		sig = key_cert;
		sig_len = get_sig_len(sig);
		if (sig_len == 0)
			return -4;
		sub = sig + sig_len;
		sub_len = get_sub_len(sub);
		if (sub_len == 0)
			return -5;
	}
}

//
// compression
//

void do_yaz0(u8 *in, u32 in_size, u8 *out, u32 out_size)
{
	u32 nout;
	u8 bits;
	u32 nbits;
	u32 n, d, i;

	bits = 0;
	nbits = 0;
	in += 0x10;
	for (nout = 0; nout < out_size; ) {
		if (nbits == 0) {
			bits = *in++;
			nbits = 8;
		}

		if ((bits & 0x80) != 0) {
			*out++ = *in++;
			nout++;
		} else {
			n = *in++;
			d = *in++;
			d |= (n << 8) & 0xf00;
			n >>= 4;
			if (n == 0)
				n = 0x10 + *in++;
			n += 2;
			d++;

			for (i = 0; i < n; i++) {
				*out = *(out - d);
				out++;
			}
			nout += n;
		}

		nbits--;
		bits <<= 1;
	};
}

//
// error handling
//

void fatal(const char *s, ...)
{
	char message[256];
	va_list ap;

	va_start(ap, s);
	vsnprintf(message, sizeof message, s, ap);

	perror(message);

	exit(1);
}

//
// output formatting
//

void print_bytes(u8 *x, u32 n)
{
	u32 i;

	for (i = 0; i < n; i++)
		fprintf(stderr, "%02x", x[i]);
}

void hexdump(u8 *x, u32 n)
{
	u32 i, j;

	for (i = 0; i < n; i += 16) {
		fprintf(stderr, "%04x:", i);
		for (j = 0; j < 16 && i + j < n; j++) {
			if ((j & 3) == 0)
				fprintf(stderr, " ");
			fprintf(stderr, "%02x", *x++);
		}
		fprintf(stderr, "\n");
	}
}

void dump_tmd(u8 *tmd)
{
	u32 i, n;
	u8 *p;

	printf("       issuer: %s\n", tmd + 0x140);
	printf("  sys_version: %016llx\n", be64(tmd + 0x0184));
	printf("     title_id: %016llx\n", be64(tmd + 0x018c));
	printf("   title_type: %08x\n", be32(tmd + 0x0194));
	printf("     group_id: %04x\n", be16(tmd + 0x0198));
	printf("title_version: %04x\n", be16(tmd + 0x01dc));
	printf(" num_contents: %04x\n", be16(tmd + 0x01de));
	printf("   boot_index: %04x\n", be16(tmd + 0x01e0));

	n = be16(tmd + 0x01de);
	p = tmd + 0x01e4;
	for (i = 0; i < n; i++) {
		printf("cid %08x  index %04x  type %04x  size %08llx\n",
		       be32(p), be16(p + 4), be16(p + 6), be64(p + 8));
		p += 0x24;
	}
}

void printHashSHA(u8 *hash) {
	int i=0;
	//printf("File SHA Hash: 0x");
	for (i=0; i<20; i++) {
		printf("%02x", hash[i]);
	}
	//printf("\n");
}

void printHashMD5(u8 *hash) {
	int i=0;
	//printf("File MD5 Hash: 0x");
	for (i=0; i<16; i++) {
		printf("%02x", hash[i]);
	}
	//printf("\n");
}

u64 getfilesize(FILE *fd) {
	u64 len_b;
	u64 len;
	len_b = ftell(fd);
	fseek(fd, 0, SEEK_END);
	len = ftell(fd);
	fseek(fd, len_b, SEEK_SET);
	return len;
}

// TMD trucha sign
int TMD_resign(u8 *tmd, u32 tmd_len) {
	u8 hash[20];
	u32 num = 0x00000000;
	u8 *sig;
	u8 *sub;
	u32 sig_len;
	u32 sub_len;
	//tmd_len += ((be16(tmd + 0x01de)-1)*0x24);
	sig = tmd;
	sig_len = get_sig_len(sig);
	if (sig_len == 0)
		return -1;
	sub = tmd + sig_len;
	sub_len = tmd_len - sig_len;
	if (sub_len == 0)
		return -2;
	
	// Set Sign to 0x00
	memset(tmd + 0x0004, 0, 256);
	// Resign TMD
	while(1) {
		sha(sub, sub_len,hash);
		//printHashSHA(hash);
		if (hash[0]==0x00) break;
		// Reserved field modification
		memcpy(tmd + 0x01D4, &num, 4);
		num++;
	}
	// the TMD is trucha signed
	printf(" %d it. ", num);
	return 1;
}

// Ticket trucha sign
int Ticket_resign(u8 *tik, u32 tik_len, u8 homebrew) {
	u8 hash[20];
	u16 num = 0x0000;
	u8 *sig;
	u8 *sub;
	u32 sig_len;
	u32 sub_len;
	u8 *new_tik;
	u8 part[16] = {0x42, 0x46, 0x47, 0x52, 0x42, 0x65, 0x46, 0x72, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x21};
	
	if (!homebrew) { // option -w enabled (watermark disabled)
		new_tik = (u8 *)malloc(676);
		memcpy(new_tik, generic_tik, 676);
		// Set title key & title id
		memcpy(new_tik+0x1BF, tik+0x1BF, 0x10);
		memcpy(new_tik+0x1DC, tik+0x1DC, 0x8);
		memcpy(tik, new_tik, 676);
		free(new_tik);
	}
	
	sig = tik;
	sig_len = get_sig_len(sig);
	if (sig_len == 0)
		return -1;
	sub = tik + sig_len;
	sub_len = tik_len - sig_len;
	if (sub_len == 0)
		return -2;
	// Set Sign to 0x00
	memset(tik + 0x0004, 0, 256);
	// Check if the ticket is already signed
	sha(sub, sub_len, hash);
	if (hash[0]==0x00) { printf(" %d it. ", num); return 1; }
	
	if (homebrew) { // Set watermark
		memcpy(tik + 0x01BF, part, 16);
	}
	// Setting parts of the trucha sign
	if (homebrew) {
		memset(tik + 0x0180, 0, 60); // Remove 60 bytes from Signature Issuer
		memset(tik + 0x01E4, 0xFF, 2); // Put 0xFF, 0xFF at the end of title ID
		memset(tik + 0x01D8, 0, 4); // Remove access rights
	}
	// Resign Ticket
	while(1) {
		sha(sub, sub_len,hash);
		//printHashSHA(hash);
		if (hash[0]==0x00) break;
		
		if (num==65535) return 0;
		// Title key mod
		memcpy(tik + 0x01F1, &num, sizeof(u16));
		num++;
	}
	// the Ticket is trucha signed
	printf(" %d it. ", num);
	return 1;
}

