#include "fscrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

/* NOTES:
 * Uses BF_cbc_encrypt. 
 * fs_encrypt and fs_decrypt allocate result buffer of at least the required
 * size and return a pointer to it. They also return the number of valid bytes 
 * in buffer in resultlen.
 * Assumes that the initialization vector contains NULL characters
 */

// encrypt plaintext of length bufsize. Use keystr as the key.
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen) {
	unsigned char IV[BLOCKSIZE];
	memset(IV, 0, BLOCKSIZE);
		
	//cast plaintext for pointer arithmetic
	unsigned const char *plaintext_ptr = (unsigned char *) plaintext;
	unsigned char *pad_block           = new unsigned char[BLOCKSIZE];

	unsigned char *ciphertext;

	//calculate number of blocks, padding, & number of unused bits.
	int num_blocks  = (bufsize / BLOCKSIZE);
	int extra_bytes = bufsize % BLOCKSIZE;
	char pad_chars  = (char) (BLOCKSIZE - extra_bytes);
	int pad_index   = extra_bytes;
	
	//always add extra block for padding
	num_blocks++;
	if (extra_bytes) {
		ciphertext = new unsigned char[BLOCKSIZE * num_blocks];
	} else {
		//size of plaintext is multiple of BLOCKSIZE - add one padded block.
		ciphertext = new unsigned char[BLOCKSIZE + BLOCKSIZE * num_blocks];
	}

	//cast key, calculate key length.
	int key_len = strlen(keystr);
	unsigned const char * key_input = (unsigned const char *) keystr;
	BF_KEY key;

 	//set key
    BF_set_key(&key, key_len, key_input);

	//encrypt each 64 bit block of plaintext.
	for (int i = 0; i < num_blocks; i++) {
		if (i == (num_blocks - 1) ) {
			//copy final block, pad 
			memcpy((char *)pad_block, (char *)plaintext_ptr+(BLOCKSIZE*i), BLOCKSIZE);
			for (int j = pad_index; j < BLOCKSIZE; j++) {
				pad_block[j] = pad_chars;
			}
			BF_cbc_encrypt(pad_block, ciphertext+(BLOCKSIZE*i), BLOCKSIZE, &key, IV, BF_ENCRYPT);
		} else {
			BF_cbc_encrypt(plaintext_ptr+(BLOCKSIZE*i), ciphertext+(BLOCKSIZE*i), BLOCKSIZE, &key, IV, BF_ENCRYPT);
		}
	}	
	*resultlen = (num_blocks * BLOCKSIZE);

	// test vals 
// 	printf("num_blocks enc: %d\n", num_blocks);
// 	printf("extra_bytes enc: %d\n", extra_bytes);
// 	printf("pad_num enc: %d\n", pad_chars);
// 	printf("pad_index enc: %d\n", pad_index);
// 	printf("resultlen enc: %d\n", *resultlen);
	
	delete[] pad_block;
	return (void *)ciphertext;
};
	
// decrypt ciphertext of length bufsize. Use keystr as the key.
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen) {
	unsigned char IV[BLOCKSIZE];
	memset(IV, 0, BLOCKSIZE);

	//cast ciphertext for pointer arithmetic
	unsigned char *ciphertext_ptr = (unsigned char *) ciphertext;

	//calculate number of blocks
	int num_blocks = bufsize / BLOCKSIZE;
	int pad_bits = 0,
		pad_num  = 0;
	    
	unsigned char *final_block = new unsigned char[BLOCKSIZE];
	unsigned char *plaintext   = new unsigned char[BLOCKSIZE * num_blocks];

	//cast key, calculate key length
	int key_len = strlen(keystr);
	unsigned const char * key_input = (unsigned const char *) keystr;
	BF_KEY key;

 	//set key
    BF_set_key(&key, key_len, key_input);

	//decrypt each 64 bit block of plaintext.
	for (int i = 0; i < num_blocks; i++) {
		BF_cbc_encrypt(ciphertext_ptr+(BLOCKSIZE*i), plaintext+(BLOCKSIZE*i), BLOCKSIZE, &key, IV, BF_DECRYPT);
		if (i == (num_blocks - 1) ) {
			//check for padding
			memcpy((char *)final_block, (char *)plaintext+(BLOCKSIZE*i), BLOCKSIZE);
			pad_num = final_block[BLOCKSIZE - 1];
			for (int j = (BLOCKSIZE - pad_num); j < BLOCKSIZE; j++) {
				if (final_block[j] == pad_num) pad_bits++;
			}			
		}
	}
	
	if (pad_bits == pad_num) {
		*resultlen = BLOCKSIZE * num_blocks - pad_num;
	}
	//called if padding fails (shouldn't happen)
	else {
		*resultlen = BLOCKSIZE * num_blocks;
	}
	
	// test vals
// 	printf("num_blocks dec: %d\n", num_blocks);
// 	printf("pad_num dec: %d\n", pad_num);
// 	printf("pad_bits dec: %d\n", pad_bits);
// 	printf("resultlen dec: %d\n", *resultlen);
	
	delete[] final_block;
	return (void *)plaintext;
};
