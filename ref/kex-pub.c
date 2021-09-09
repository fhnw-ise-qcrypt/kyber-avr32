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

int main( int argc, char *argv[] )
{
  *argv[0] = 0;
  int i;

  // no arguments provided, just print own public key
  if( argc < 2 ) {
    if( access("./SKA.key", F_OK ) == 0 && access("./PKA.key", F_OK ) == 0 ) {
      printf("[ ok  ]\n");
    }
    return 0;
  }

  // -p argument contains Bobs Public key
  else if( argv[1][0] == '-' && argv[1][1] == 'p' ){
    if( argc > 2){
      uint8_t pkb[CRYPTO_PUBLICKEYBYTES];
      for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++) pkb[i] = 0;
      stdinHexString((char*)argv[2], pkb, CRYPTO_PUBLICKEYBYTES);
      writeHexFile("./PKB.key", pkb, CRYPTO_PUBLICKEYBYTES);
    } else {
      printf("error -p: no key provided.\n");
      return -1;
    }
  }

  // -A start key exchange as Alice
  else if( argv[1][0] == '-' && argv[1][1] == 'A' ){
    if( access("./ESKA.key", F_OK ) == 0 && access("./TK.key", F_OK ) == 0 ) {
      printf("error: there is already a key exchange ongoing.\n");
      return -1;
    } 
    if( access("./PKB.key", F_OK ) != 0 ) {
      printf("error: public key of other party is not known.\n");
      return -1;
    }
    uint8_t pkb[CRYPTO_PUBLICKEYBYTES];
    uint8_t eska[CRYPTO_SECRETKEYBYTES];
    uint8_t ake_senda[KEX_AKE_SENDABYTES];
    uint8_t tk[KEX_SSBYTES];

    for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++) pkb[i] = 0;
    for(i=0;i<CRYPTO_SECRETKEYBYTES;i++) eska[i] = 0;
    for(i=0;i<KEX_AKE_SENDABYTES;i++) ake_senda[i] = 0;
    for(i=0;i<KEX_SSBYTES;i++) tk[i] = 0;

    // retreive stored Public Key
    readHexFile("./PKB.key", pkb, CRYPTO_PUBLICKEYBYTES);

    kex_ake_initA(ake_senda, tk, eska, pkb); // Run by Alice
    // kex_ake_initA(ake_senda, tk, eska, pkb);

    // save temporary variables
    writeHexFile("./TK.key", tk, KEX_SSBYTES);
    writeHexFile("./ESKA.key", eska, CRYPTO_SECRETKEYBYTES);
    writeHexFile("./ake_senda.txt", ake_senda, KEX_AKE_SENDABYTES);
    // send to Bob
    printf("Send \"ake_senda.txt\" to other party.\n");
    // printHexString("Send to other Party:", ake_senda, KEX_AKE_SENDABYTES);
  }

  // continue as Bob
  else if( argv[1][0] == '-' && argv[1][1] == 'B' ){
    uint8_t ka[KEX_SSBYTES];
    uint8_t ska[CRYPTO_SECRETKEYBYTES];
    uint8_t ake_senda[KEX_AKE_SENDABYTES];
    uint8_t ake_sendb[KEX_AKE_SENDBBYTES];
    uint8_t pkb[CRYPTO_PUBLICKEYBYTES];

    for(i=0;i<KEX_SSBYTES;i++) ka[i] = 0;
    for(i=0;i<CRYPTO_SECRETKEYBYTES;i++) ska[i] = 0;
    for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++) pkb[i] = 0;
    for(i=0;i<KEX_AKE_SENDABYTES;i++) ake_senda[i] = 0;
    for(i=0;i<KEX_AKE_SENDBBYTES;i++) ake_sendb[i] = 0;

    if( argc > 2){
      // read command line argument from other party
      stdinHexString((char*)argv[2], ake_senda, KEX_AKE_SENDABYTES);
    } else if( access("./ake_senda.txt", F_OK ) == 0 ) {
      readHexFile("./ake_senda.txt", ake_senda, KEX_AKE_SENDABYTES); 
    } else {
      printf("error -B: no message (stdin or file) provided.\n");
      return -1;
    }
    // retreive stored own private key
    readHexFile("./SKA.key", ska, CRYPTO_SECRETKEYBYTES);
    readHexFile("./PKB.key", pkb, CRYPTO_PUBLICKEYBYTES);

    // from the perspective of Bob it should be:
    // skb = ska / pka = pkb 
    // but it is not! WHY ???
    kex_ake_sharedB(ake_sendb, ka, ake_senda, ska, pkb); // Run by Bob
    // kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pkb);
    writeHexFile("./ake_sendb.txt", ake_sendb, KEX_AKE_SENDBBYTES);

    //printHexString("Send to other party: ", ake_sendb, KEX_AKE_SENDBBYTES);
    printf("Send \"ake_sendb.txt\" to other party.\n");
    printHexString("Shared secret: ", ka, KEX_SSBYTES);

    // save common key
    writeHexFile("./COMMON.key", ka, KEX_SSBYTES);
  }

  // finish as Alice
  else if( argv[1][0] == '-' && argv[1][1] == 'C' ){
    uint8_t tk[KEX_SSBYTES];
    uint8_t ka[KEX_SSBYTES];
    uint8_t eska[CRYPTO_SECRETKEYBYTES];
    uint8_t ska[CRYPTO_SECRETKEYBYTES];
    uint8_t ake_sendb[KEX_AKE_SENDBBYTES];

    for(i=0;i<KEX_SSBYTES;i++) ka[i] = 0;
    for(i=0;i<KEX_SSBYTES;i++) tk[i] = 0;
    for(i=0;i<CRYPTO_SECRETKEYBYTES;i++) eska[i] = 0;
    for(i=0;i<CRYPTO_SECRETKEYBYTES;i++) ska[i] = 0;
    for(i=0;i<KEX_AKE_SENDBBYTES;i++) ake_sendb[i] = 0;

    if( argc > 2 ){
      // read command line argument from other party
      stdinHexString((char*)argv[2], ake_sendb, KEX_AKE_SENDBBYTES);
    } else if( access("./ake_sendb.txt", F_OK ) == 0 ) {
      readHexFile("./ake_sendb.txt", ake_sendb, KEX_AKE_SENDBBYTES);
    } else {
      printf("error -s: no key provided.\n");
      return -1;
    }
    if( access("./ESKA.key", F_OK ) == 0 && access("./TK.key", F_OK ) == 0 ) {

      // retreive stored TK variable
      readHexFile("./TK.key", tk, KEX_SSBYTES);
      readHexFile("./SKA.key", ska, CRYPTO_SECRETKEYBYTES);
      readHexFile("./ESKA.key", eska, CRYPTO_SECRETKEYBYTES);

      kex_ake_sharedA(ka, ake_sendb, tk, eska, ska); // Run by Alice
      // kex_ake_sharedA(ka, ake_sendb, tk, eska, ska);

      printHexString("Shared secret: ", ka, KEX_SSBYTES);

      // save common key
      writeHexFile("./COMMON.key", ka, KEX_SSBYTES);
    } else {
      printf("error: the other party's public key is not known.\n");
    }
  }

  return 0;
}

