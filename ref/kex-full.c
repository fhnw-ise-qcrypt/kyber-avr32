#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "kem.h"
#include "kex.h"

#include "kex-helper.h"

/**
 * kex-pub
 * 
 * performs key exchange
 */ 

int main()
{
  int i;
  uint8_t pka[CRYPTO_PUBLICKEYBYTES];
  uint8_t pkb[CRYPTO_PUBLICKEYBYTES];
  uint8_t ska[CRYPTO_SECRETKEYBYTES];
  uint8_t skb[CRYPTO_SECRETKEYBYTES];
  uint8_t ake_senda[KEX_AKE_SENDABYTES];
  uint8_t ake_sendb[KEX_AKE_SENDBBYTES];
  uint8_t ake_senda_stdio[KEX_AKE_SENDABYTES];
  uint8_t ake_sendb_stdio[KEX_AKE_SENDBBYTES];
  uint8_t eska[CRYPTO_SECRETKEYBYTES];
  uint8_t tk[KEX_SSBYTES];
  uint8_t ka[KEX_SSBYTES];
  uint8_t kb[KEX_SSBYTES];

  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++){pkb[i]=0;pka[i]=0;eska[i]=0;}
  for(i=0;i<KEX_AKE_SENDABYTES;i++){ake_senda[i]=0;}
  for(i=0;i<KEX_AKE_SENDBBYTES;i++){ake_sendb[i]=0;}
  for(i=0;i<KEX_SSBYTES;i++){tk[i]=0;ka[i]=0;kb[i]=0;}

  crypto_kem_keypair(pka, ska); // Generate static key for Alice
  crypto_kem_keypair(pkb, skb); // Generate static key for Bob

  writeHexFile("./PKA.key", pka, CRYPTO_PUBLICKEYBYTES);
  writeHexFile("./PKB.key", pkb, CRYPTO_PUBLICKEYBYTES);
  writeHexFile("./SKA.key", ska, CRYPTO_SECRETKEYBYTES);
  writeHexFile("./SKB.key", skb, CRYPTO_SECRETKEYBYTES);

  /* 1. stage ALICE */
  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++){pkb[i]=0;pka[i]=0;eska[i]=0;}
  for(i=0;i<KEX_AKE_SENDABYTES;i++){ake_senda[i]=0;ake_senda_stdio[i]=0;}
  for(i=0;i<KEX_AKE_SENDBBYTES;i++){ake_sendb[i]=0;ake_sendb_stdio[i]=0;}
  for(i=0;i<KEX_SSBYTES;i++){tk[i]=0;ka[i]=0;kb[i]=0;}

  readHexFile("./PKB.key", pkb, CRYPTO_PUBLICKEYBYTES);

  kex_ake_initA(ake_senda, tk, eska, pkb);

  writeHexFile("./TK.key", tk, KEX_SSBYTES);
  writeHexFile("./ESKA.key", eska, CRYPTO_SECRETKEYBYTES);

  printHexString("Send to other Party:", ake_senda, KEX_AKE_SENDABYTES);

  /* 2. stage BOB */
  readHexString("Enter the above message > ", ake_senda_stdio, KEX_AKE_SENDABYTES);
  verifyArrays("send_a", ake_senda, ake_senda_stdio, KEX_AKE_SENDABYTES);

  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++){pkb[i]=0;pka[i]=0;eska[i]=0;}
  for(i=0;i<KEX_SSBYTES;i++){tk[i]=0;ka[i]=0;kb[i]=0;}

  readHexFile("./PKA.key", pka, CRYPTO_PUBLICKEYBYTES);

  kex_ake_sharedB(ake_sendb, kb, ake_senda_stdio, skb, pka);
  writeHexFile("./KB.key", kb, KEX_SSBYTES);
  printHexString("[ ok  ] Common Key of B:", kb, KEX_SSBYTES);
  printHexString("Send to other Party:", ake_sendb, KEX_AKE_SENDBBYTES);

  /* 3. stage ALICE */
  readHexString("Enter the above message > ", ake_sendb_stdio, KEX_AKE_SENDBBYTES);
  verifyArrays("send_b", ake_sendb, ake_sendb_stdio, KEX_AKE_SENDBBYTES);

  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++){pkb[i]=0;pka[i]=0;eska[i]=0;}

  readHexFile("./TK.key", tk, KEX_SSBYTES);
  readHexFile("./ESKA.key", eska, CRYPTO_SECRETKEYBYTES);
  readHexFile("./SKA.key", ska, CRYPTO_SECRETKEYBYTES);

  kex_ake_sharedA(ka, ake_sendb_stdio, tk, eska, ska);

  writeHexFile("./KA.key", ka, KEX_SSBYTES);
  printHexString("[ ok  ] Common Key of A:", ka, KEX_SSBYTES);
  verifyArrays("ka/kb", ka, kb, KEX_SSBYTES);

  return 0;
}

