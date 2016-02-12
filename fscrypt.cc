#include "fscrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

/* NOTES:
 * Uses BF_set_key and BF_ecb_encrypt (not BF_cbc_encrypt). 
 * fs_encrypt and fs_decrypt allocate result buffer of at least the required
 * size and return a pointer to it. They also return the number of valid bytes 
 * in buffer in resultlen.
 */

// encrypt plaintext of length bufsize. Use keystr as the key.
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen) {

	//cast plaintext for pointer arithmetic
	unsigned const char *plaintext_ptr = (unsigned char *) plaintext;
	unsigned char *pad_block           = new unsigned char[BLOCKSIZE];
	unsigned char *chained_pad_block   = new unsigned char[BLOCKSIZE];
	unsigned char *ciphertext_block    = new unsigned char[BLOCKSIZE];
	unsigned char *ciphertext;

	//calculate number of blocks, padding, & number of unused bits.
	int num_blocks  = (bufsize / BLOCKSIZE),
	    extra_bytes = bufsize % BLOCKSIZE,
		pad_index   = extra_bytes;
	char pad_chars  = (char) (BLOCKSIZE - extra_bytes);
	
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
		//XOR plaintext with IV
		memcpy((char *)pad_block, (char *)plaintext_ptr + (BLOCKSIZE * i), BLOCKSIZE);
		if (i == 0 && num_blocks > 1) {
			for (int j = 0; j < BLOCKSIZE; j++) {
				chained_pad_block[j] = pad_block[j] ^ 0x00;
			}
		//pad
		} else if (i == num_blocks - 1) {
			memcpy((char *)ciphertext_block, (char *)ciphertext + (BLOCKSIZE * (i-1)), BLOCKSIZE);
			for (int j = pad_index; j < BLOCKSIZE; j++) {
				pad_block[j] = pad_chars;
			}
			if (num_blocks == 1) {
				for (int j = 0; j < BLOCKSIZE; j++) {
					chained_pad_block[j] = pad_block[j] ^ 0x00;
				}			
			} else {
				//XOR with previous ciphertext
				for (int j = 0; j < BLOCKSIZE; j++) {
					chained_pad_block[j] = pad_block[j] ^ ciphertext_block[j];
				}
			}
		} else {
			memcpy((char *)ciphertext_block, (char *)ciphertext + (BLOCKSIZE * (i-1)), BLOCKSIZE);
			for (int j = 0; j < BLOCKSIZE; j++) {
				chained_pad_block[j] = pad_block[j] ^ ciphertext_block[j];
			}
		}
		BF_ecb_encrypt(chained_pad_block, ciphertext + (BLOCKSIZE * i), &key, BF_ENCRYPT);
	}	
	*resultlen = (num_blocks * BLOCKSIZE);

	// test vals 
// 	printf("num_blocks enc: %d\n", num_blocks);
// 	printf("extra_bytes enc: %d\n", extra_bytes);
// 	printf("pad_num enc: %d\n", pad_chars);
// 	printf("pad_index enc: %d\n", pad_index);
// 	printf("resultlen enc: %d\n", *resultlen);
	
	delete[] pad_block;
	delete[] chained_pad_block;
	delete[] ciphertext_block;
	return (void *)ciphertext;
};
	
// decrypt ciphertext of length bufsize. Use keystr as the key.
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen) {
	
	//cast ciphertext for pointer arithmetic
	unsigned char *ciphertext_ptr = (unsigned char *) ciphertext;

	//calculate number of blocks & number of unused bits.
	int num_blocks = bufsize / BLOCKSIZE;
	int pad_bits = 0,
		pad_num  = 0;
	    
	unsigned char *final_block     = new unsigned char[BLOCKSIZE];
	unsigned char *plaintext       = new unsigned char[BLOCKSIZE * num_blocks];
	unsigned char *prev_ciphertext = new unsigned char[BLOCKSIZE];

	//cast key, calculate key length.
	int key_len = strlen(keystr);
	unsigned const char * key_input = (unsigned const char *) keystr;
	BF_KEY key;

 	//set key
    BF_set_key(&key, key_len, key_input);

	//decrypt each 64 bit block of plaintext.
	for (int i = 0; i < num_blocks; i++) {
		BF_ecb_encrypt(ciphertext_ptr + (BLOCKSIZE * i), plaintext + (BLOCKSIZE * i), &key, BF_DECRYPT);
		memcpy((char *)final_block, (char *)plaintext + (BLOCKSIZE * i), BLOCKSIZE);
		if (i == 0) {
			for (int j = 0; j < BLOCKSIZE; j++) {
				plaintext[BLOCKSIZE*i+j] = final_block[j] ^ 0x00;
			}
		}		
		else if (i > 0) {
			memcpy((char *)prev_ciphertext, (char *)ciphertext_ptr + (BLOCKSIZE * (i-1)), BLOCKSIZE);		
			for (int j = 0; j < BLOCKSIZE; j++) {
				plaintext[BLOCKSIZE*i+j] = final_block[j] ^ prev_ciphertext[j];
			}
		}
		if (i == (num_blocks - 1) ) {
			//check for padding
			memcpy((char *)final_block, (char *)plaintext + (BLOCKSIZE * i), BLOCKSIZE);
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
	
	delete[] prev_ciphertext;
	delete[] final_block;
	return (void *)plaintext;
};

