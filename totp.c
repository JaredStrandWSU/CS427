#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdint.h>

#define RUN  0
#define TEST  1

/////////////////////
// This code based off TOTP RFC 6238 implementation
// https://tools.ietf.org/html/rfc6238
/////////////////////


int32_t compute_totp(const unsigned char *seed, uint32_t message ){
    unsigned int result_len;
    char result[128];
	unsigned char *hash = NULL;
    int offset = 0;
    char text[8];

    for (int i = 7; i >= 0; i--)
    {
        text[i] = (char)(message & 0xff);
        message = message >> 8;
    }

	hash = HMAC(EVP_sha512(), seed, strlen(seed), text, 8u, result, &result_len);


    offset = result[result_len - 1] & 0xf;

   printf("Offset = %d \n", offset);

    int32_t binary =((hash[offset] & 0x7f) << 24) |
                    ((hash[offset + 1] & 0xff) << 16) |
                    ((hash[offset + 2] & 0xff) << 8) |
                    (hash[offset + 3] & 0xff);

   // printf("new Hash ptr val= %d \n", hash);

    binary %= 100000000;
    return binary; 
}

int32_t main (int argc, char *argv[])
{
    int8_t argsok = 0; 
    int8_t mode=0;
    time_t T;
    unsigned char seed[] = "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34";

    if (argc > 1){
        if(strncmp(argv[1], "run", 3)==0){
            mode = RUN; 
            argsok=1;
        }
        else if (strncmp(argv[1], "test", 4)==0){
            argsok=1;
            mode = TEST; 
        }
    }
    if(!argsok){
        perror("'./totp test' or './totp run'\n");
        exit(1);
    }
    if (mode == RUN){

        time (&T);
        T = (uint32_t)(T/30);
        printf("Time: %llx, OTP: %d\n", T, compute_totp(seed, (uint32_t)T));
    }
    else{
        T = 0x0000000000000001;
        printf("Time: %lld, OTP: %d\n", T, compute_totp(seed, (uint32_t)T));
        T = 0x00000000023523EC; 
        printf("Time: %lld, OTP: %d\n", T, compute_totp(seed, T));
        T = 0x00000000023523ED;
        printf("Time: %llx, OTP: %d\n", T, compute_totp(seed, T));
        T = 0x000000000273EF07;
        printf("Time: %llx, OTP: %d\n", T, compute_totp(seed, T));
        T = 0x0000000003F940AA;
        printf("Time: %llx, OTP: %d\n", T, compute_totp(seed, T));
        T = 0x0000000027BC86AA;
        printf("Time: %llx, OTP: %d\n", T, compute_totp(seed, T));
    }

    return 0;
}


//compute totp ( )