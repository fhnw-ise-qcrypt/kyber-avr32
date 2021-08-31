#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "kem.h"
#include "kex.h"
#include "kex-helper.h"

/**
 * kex-init
 * 
 * Generates a public/secret keypair
 */ 

int main(void)
{
  int i;
  uint8_t pka[CRYPTO_PUBLICKEYBYTES];
  uint8_t ska[CRYPTO_SECRETKEYBYTES];
  uint8_t pkt[CRYPTO_PUBLICKEYBYTES];
  uint8_t skt[CRYPTO_SECRETKEYBYTES];
  for(i=0;i<CRYPTO_SECRETKEYBYTES;i++){ska[i]=0;skt[i]=0;}
  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++){pka[i]=0;pkt[i]=0;}

  crypto_kem_keypair(pka, ska); // Generate static key for Alice

  if( access("./SKA.key", F_OK ) == 0 || access("./PKA.key", F_OK ) == 0 ) {
      printf("error: keys already initialized.\nUse kex-del to remove them.\n");
      return -1;
  }

  writeHexFile("./SKA.key", ska, CRYPTO_SECRETKEYBYTES);
  writeHexFile("./PKA.key", pka, CRYPTO_PUBLICKEYBYTES);
  printHexString("[ ok  ] my public key is:", pka, CRYPTO_PUBLICKEYBYTES);

  readHexFile("./SKA.key", skt, CRYPTO_SECRETKEYBYTES);
  readHexFile("./PKA.key", pkt, CRYPTO_PUBLICKEYBYTES);
  
  verifyArrays("SKA", ska, skt, CRYPTO_SECRETKEYBYTES);
  verifyArrays("PKA", pka, pkt, CRYPTO_PUBLICKEYBYTES);

  return 0;
}

