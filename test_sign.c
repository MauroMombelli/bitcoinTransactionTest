//compiled with gcc -g -lssl -lcrypto
#include <openssl/ec.h>		// for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>	// for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h>	// for NID_secp192k1
#include <openssl/sha.h>

#include <stdio.h>

#include <stdint.h>
#include <stddef.h>

int create_signature (uint8_t * hash, int len)
{
/*
  // convert priv key from hexadecimal to BIGNUM
  uint8_t hex[] =
    { 0x0C, 0xAE, 0xCF, 0x01, 0xD7, 0x41, 0x02, 0xA2, 0x8A, 0xED, 0x6A, 0x64,
0xDC, 0xF1, 0xCF, 0x7B, 0x0E, 0x41, 0xC4, 0xDD, 0x6C, 0x62, 0xF7, 0x0F, 0x46, 0xFE,
0xBD, 0xC3, 0x25, 0x14, 0xF0, 0xBD };*/
	EC_KEY *eckey = NULL;
	EC_POINT *pub_key = NULL;
	const EC_GROUP *group = NULL;
	BIGNUM start;
	BIGNUM *res;
	BN_CTX *ctx;
	BN_init(&start);
	ctx = BN_CTX_new(); // ctx is an optional buffer to save time from allocating and deallocating memory whenever required
	
	res = &start;
	BN_hex2bn(&res,"0caecf01d74102a28aed6a64dcf1cf7b0e41c4dd6c62f70f46febdc32514f0bd");
	eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	group = EC_KEY_get0_group(eckey);
	
	
	EC_KEY_set_private_key(eckey, res);
	
	int function_status = -1;
	if (NULL == eckey)
	{
		printf ("\nFailed to create new EC Key\n");
		function_status = -1;
	}else{
		unsigned int nSize = ECDSA_size(eckey);
		uint8_t ris[nSize];
		if (!ECDSA_sign(0, hash, sizeof(hash), ris, &nSize, eckey)){
			printf ("\nFailed to generate EC Signature\n");
		}else{
			printf ("\nOK to generate EC Signature len: %d \n", nSize);
			for (int i=0;i<nSize; i++){
				printf ("%02X", ris[i]);
			}
			
			{
				pub_key = EC_POINT_new(group);
				if (!EC_POINT_mul(group, pub_key, res, NULL, NULL, ctx))
					printf("Error at EC_POINT_mul.\n");
				EC_KEY_set_public_key(eckey, pub_key);
	
				char *cc = EC_POINT_point2hex(group, pub_key, 4, ctx);

				char *c=cc;

				int i;

				printf("\npublic key:");
				for (i=0; i<130; i++) // 1 byte 0x42, 32 bytes for X coordinate, 32 bytes for Y coordinate
				{
					printf("%c", *c++);
				}
				free(cc);
			}
			int verify_status = ECDSA_verify(0, hash, sizeof(hash), ris, nSize, eckey);
			const int verify_success = 1;
			if (verify_success != verify_status)
			{
				printf("\nFailed to verify EC Signature\n");
				function_status = -1;
			}else{
				printf("\nVerifed EC Signature\n");
				function_status = 1;
			}
		}
		EC_KEY_free (eckey);
	}
	return function_status;
}

int main(){
	uint8_t double_hash[] = {0x5f,0xda,0x68,0x72,0x9a,0x63,0x12,0xe1,0x7e,0x64,0x1e,0x9a,0x49,0xfa,0xc2,0xa4,0xa6,0xa6,0x80,0x12,0x66,0x10,0xaf,0x57,0x3c,0xaa,0xb2,0x70,0xd2,0x32,0xf8,0x50};
	printf ("\nhash len: %d \n", sizeof(double_hash));
	create_signature( double_hash, sizeof(double_hash) );
}
