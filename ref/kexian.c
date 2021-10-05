#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "kem.h"
#include "kex.h"
#include "kexian.h"
#include "kex-helper.h"

uint8_t ska[CRYPTO_SECRETKEYBYTES];
uint8_t ake_senda[KEX_AKE_SENDABYTES];
uint8_t ake_sendb[KEX_AKE_SENDBBYTES];
uint8_t eska[CRYPTO_SECRETKEYBYTES];
uint8_t tk[KEX_SSBYTES];
uint8_t ka[KEX_SSBYTES];
uint8_t pka[CRYPTO_PUBLICKEYBYTES];
uint8_t pkb[CRYPTO_PUBLICKEYBYTES];

int cmd_kex_kyber_init(struct command_context *ctx);
int cmd_kex_kyber_pub(struct command_context *ctx);
int cmd_kex_kyber_initA(struct command_context *ctx);
int cmd_kex_kyber_sharedA(struct command_context *ctx);
int cmd_kex_kyber_sharedB(struct command_context *ctx);

int cmd_kex_kyber_init(struct command_context *ctx) {
  int i;
  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++){pkb[i]=0;pka[i]=0;}
  for(i=0;i<CRYPTO_SECRETKEYBYTES;i++){ska[i]=0;eska[i]=0;}  // CHANGE here
  for(i=0;i<KEX_AKE_SENDABYTES;i++){ake_senda[i]=0;}
  for(i=0;i<KEX_AKE_SENDBBYTES;i++){ake_sendb[i]=0;}
  for(i=0;i<KEX_SSBYTES;i++){tk[i]=0;ka[i]=0;}

  crypto_kem_keypair(pka, ska); // Generate static keypair for Alice
  writeHexFile(KEX_FILE_SKA, ska, CRYPTO_SECRETKEYBYTES);
  writeHexFile(KEX_FILE_PKA, pka, CRYPTO_PUBLICKEYBYTES);
  ctx->dummy++;

  return 0;
}

int cmd_kex_kyber_pub(struct command_context *ctx) {
  if (ctx->argc != 2){
    // no argument provided, read from file
    FILE *fp;
    fp = fopen(KEX_FILE_PKB, "r");
    if( fp != NULL ){
      readHexFile(KEX_FILE_PKB, pkb, CRYPTO_PUBLICKEYBYTES);
    } else {
      printf("%s not found\n", KEX_FILE_PKB);
      return -1;
    }
      fclose(fp);
  } else {
    stdinHexString((char*)ctx->argv[1], pkb, CRYPTO_PUBLICKEYBYTES);
  }
  return 0;
}

/**
 * @note initialize the key exchange here and send ake_senda.txt to GND
 * */
int cmd_kex_kyber_initA(struct command_context *ctx) {
  // todo: verify that ESKA / TK are empty
  // todo: verify that PKB is non empty

  kex_ake_initA(ake_senda, tk, eska, pkb);
  // printHexString("Message to other party:", ake_senda, KEX_AKE_SENDABYTES);
  
  writeHexFile(KEX_FILE_SENDA, ake_senda, KEX_AKE_SENDABYTES);
  writeHexFile(KEX_FILE_ESKA, eska, CRYPTO_SECRETKEYBYTES);  // CHANGE here
  writeHexFile(KEX_FILE_TK, tk, KEX_SSBYTES);

  printf("Send %s to other party\n", KEX_FILE_SENDA);
  ctx->dummy++;
  return 0;
}

/**
 * @note the GND initialized key exchange and sent "ake_senda.txt" to here
 * process the ake_senda here
 * */
int cmd_kex_kyber_sharedB(struct command_context *ctx) {
  if (ctx->argc != 2) {
    // no argument provided, read from file
    readHexFile(KEX_FILE_SENDA, ake_senda, KEX_AKE_SENDABYTES);
  } else {
    stdinHexString((char*)ctx->argv[1], ake_senda, KEX_AKE_SENDABYTES);
  }
  kex_ake_sharedB(ake_sendb, ka, ake_senda, ska, pkb); // Run by Bob

  // printHexString("Message to other party: ", ake_sendb, KEX_AKE_SENDBBYTES);
  writeHexFile(KEX_FILE_SENDA, ake_sendb, KEX_AKE_SENDBBYTES);
  printf("Send %s to other party\n", KEX_FILE_SENDA);
  //printHexString("Shared Secret: ", ka, KEX_SSBYTES);

  return 0;
}

/**
 * @brief finish up the key exchange
 * */
int cmd_kex_kyber_sharedA(struct command_context *ctx) {
  if (ctx->argc != 2){
    // no argument provided, read from file
    readHexFile(KEX_FILE_SENDB, ake_sendb, KEX_AKE_SENDBBYTES);
  } else {
    stdinHexString((char*)ctx->argv[1], ake_sendb, KEX_AKE_SENDBBYTES);
  }

  // load from files in case of restart of OBC
  if( (tk[0]==0) && (tk[1]==0) && (tk[2]==0) &&
    (eska[0]==0) && (eska[1]==0) && (eska[2]==0)){
    printf("open from file\n");
    FILE *fp;
    fp = fopen(KEX_FILE_TK, "r");
    if( fp != NULL ){
      readHexFile(KEX_FILE_TK, tk, KEX_SSBYTES);
    } 
    fp = fopen(KEX_FILE_ESKA, "r");
    if( fp != NULL ){
      readHexFile(KEX_FILE_ESKA, eska, CRYPTO_SECRETKEYBYTES);
    } 
    fp = fopen(KEX_FILE_SKA, "r");
    if( fp != NULL ){
      readHexFile(KEX_FILE_SKA, ska, CRYPTO_SECRETKEYBYTES);
    } 
  }

  kex_ake_sharedA(ka, ake_sendb, tk, eska, ska); // Run by Alice
  printHexString("Shared secret: ", ka, KEX_SSBYTES);
  writeHexFile(KEX_FILE_COMMON, ka, KEX_SSBYTES);

  return 0;
}


int main(void)
{
  struct command_context ctx;

/*
  char argv0[] = "-i";
  char *argv_0[] = {argv0, NULL};
  ctx.argv = argv_0;
  ctx.argc = 1;

  cmd_kex_kyber_init(&ctx);

  char argv1[] = "-p";
  char *argv_1[] = {argv1, NULL};
  ctx.argv = argv_1;
  ctx.argc = 1;

  cmd_kex_kyber_pub(&ctx);

  char argv2[] = "-A";
  char *argv_2[] = {argv2, NULL};
  ctx.argv = argv_2;
  ctx.argc = 1;

  cmd_kex_kyber_initA(&ctx);
*/
  
  char argv0[] = "-C";
  char *argv_0[] = {argv0, NULL};
  ctx.argv = argv_0;
  ctx.argc = 1;

  cmd_kex_kyber_sharedA(&ctx);
  


  return 0;
}


