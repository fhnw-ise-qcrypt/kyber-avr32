#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kem.h"
#include "kex.h"

int main(void)
{
  uint8_t pkb[CRYPTO_PUBLICKEYBYTES];
  uint8_t skb[CRYPTO_SECRETKEYBYTES];
  uint8_t pkb_temp[CRYPTO_PUBLICKEYBYTES];

  uint8_t pka[CRYPTO_PUBLICKEYBYTES];
  uint8_t ska[CRYPTO_SECRETKEYBYTES];
  uint8_t pka_temp[CRYPTO_PUBLICKEYBYTES];

  uint8_t eska[CRYPTO_SECRETKEYBYTES];

  uint8_t uake_senda[KEX_UAKE_SENDABYTES];
  uint8_t uake_sendb[KEX_UAKE_SENDBBYTES];

  uint8_t ake_senda[KEX_AKE_SENDABYTES];
  uint8_t ake_sendb[KEX_AKE_SENDBBYTES];
  uint8_t ake_tempa[KEX_AKE_SENDABYTES];
  uint8_t ake_tempb[KEX_AKE_SENDBBYTES];

  uint8_t tk[KEX_SSBYTES];
  uint8_t ka[KEX_SSBYTES];
  uint8_t kb[KEX_SSBYTES];
  uint8_t zero[KEX_SSBYTES];
  int i;

  for(i=0;i<KEX_SSBYTES;i++)
    zero[i] = 0;

  printf("KEX_SSBYTES: %d (%d)\n", KEX_SSBYTES, KEX_SSBYTES*2);
  printf("KEX_AKE_SENDABYTES: %d (%d)\n", KEX_AKE_SENDABYTES, KEX_AKE_SENDABYTES*2);
  printf("KEX_AKE_SENDBBYTES: %d (%d)\n", KEX_AKE_SENDBBYTES, KEX_AKE_SENDBBYTES*2);
  printf("CRYPTO_SECRETKEYBYTES: %d (%d)\n", CRYPTO_SECRETKEYBYTES, CRYPTO_SECRETKEYBYTES*2);
  printf("CRYPTO_PUBLICKEYBYTES: %d (%d)\n", CRYPTO_PUBLICKEYBYTES, CRYPTO_PUBLICKEYBYTES*2);

  crypto_kem_keypair(pkb, skb); // Generate static key for Bob

  crypto_kem_keypair(pka, ska); // Generate static key for Alice

  printf("Public Key of Alice: \n > ");
  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++){
    printf("%02x", pka[i]);
  }
  printf("\n");
  printf("Public Key of Bob: \n > ");
  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++){
    printf("%02x", pkb[i]);
  }
  printf("\n");

  char *line = NULL;
  size_t len = 0;
  ssize_t lineSize = 0;

  // Perform unilaterally authenticated key exchange

  kex_uake_initA(uake_senda, tk, eska, pkb); // Run by Alice

  kex_uake_sharedB(uake_sendb, kb, uake_senda, skb); // Run by Bob

  kex_uake_sharedA(ka, uake_sendb, tk, eska); // Run by Alice

  if(memcmp(ka,kb,KEX_SSBYTES))
    printf("Error in UAKE\n");

  if(!memcmp(ka,zero,KEX_SSBYTES))
    printf("Error: UAKE produces zero key\n");

  if(memcmp(ka,kb,KEX_SSBYTES))
    printf("Error in AKE\n");
  if(memcmp(ka,kb,KEX_SSBYTES)){
    printf("N bytes: %d\n", KEX_SSBYTES);
    for(i=0;i<KEX_SSBYTES;i++){
      if(memcmp(&ka[i],&kb[i],1)){
        printf("ka[%d] = %02x | kb[%d] = %02x\n", i, ka[i], i, kb[i]);
      }
    }
  }

  // Perform mutually authenticated key exchange

  printf("Enter Bob's Public Key:\n > ");
  len = 0;
  lineSize = 0;
  lineSize = getline(&line, &len, stdin);
  printf("\n");
  printf("SENDBYTES=%d / linesize=%ld\n\n", CRYPTO_PUBLICKEYBYTES, lineSize/2);
  for(i=0;(i<CRYPTO_PUBLICKEYBYTES)&&(i<lineSize);i++){
    char tmp[3] = {line[2*i], line[2*i+1], 0};
    pkb_temp[i] = (uint8_t)strtol(tmp,NULL,16);
  }
  free(line);
  printf("\n");

  //kex_ake_initA(ake_senda, tk, eska, pkb); // Run by Alice
  kex_ake_initA(ake_senda, tk, eska, pkb_temp); // Run by Alice

  printf("Alice sends to Bob: \n > ");
  for(i=0;i<KEX_AKE_SENDABYTES;i++){
    printf("%02x", ake_senda[i]);
  }
  printf("\n");

  printf("Enter what Bob received:\n > ");
  len = 0;
  lineSize = 0;
  lineSize = getline(&line, &len, stdin);
  printf("\n");
  printf("SENDBYTES=%d / linesize=%ld\n\n", KEX_AKE_SENDABYTES, lineSize/2);
  for(i=0;(i<KEX_AKE_SENDABYTES)&&(i<lineSize);i++){
    char tmp[3] = {line[2*i], line[2*i+1], 0};
    ake_tempa[i] = (uint8_t)strtol(tmp,NULL,16);
  }
  free(line);
  printf("\n");

  printf("Enter Alice's Public Key:\n > ");
  len = 0;
  lineSize = 0;
  lineSize = getline(&line, &len, stdin);
  printf("\n");
  printf("SENDBYTES=%d / linesize=%ld\n\n", CRYPTO_PUBLICKEYBYTES, lineSize/2);
  for(i=0;(i<CRYPTO_PUBLICKEYBYTES)&&(i<lineSize);i++){
    char tmp[3] = {line[2*i], line[2*i+1], 0};
    pka_temp[i] = (uint8_t)strtol(tmp,NULL,16);
  }
  free(line);
  printf("\n");

  //kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka_temp); // Run by Bob
  kex_ake_sharedB(ake_sendb, kb, ake_tempa, skb, pka_temp); // Run by Bob
  printf("Bob sends to Alice: \n > ");
  for(i=0;i<KEX_AKE_SENDBBYTES;i++){
    printf("%02x", ake_sendb[i]);
  }
  printf("\n");

  printf("Enter what Alice received:\n > ");
  len = 0;
  lineSize = 0;
  lineSize = getline(&line, &len, stdin);
  printf("\n");
  printf("SENDBYTES=%d / linesize=%ld\n\n", KEX_AKE_SENDBBYTES, lineSize/2);
  for(i=0;(i<KEX_AKE_SENDBBYTES)&&(i<lineSize);i++){
    char tmp[3] = {line[2*i], line[2*i+1], 0};
    ake_tempb[i] = (uint8_t)strtol(tmp,NULL,16);
  }
  free(line);
  printf("\n");

  //kex_ake_sharedA(ka, ake_sendb, tk, eska, ska); // Run by Alice
  kex_ake_sharedA(ka, ake_tempb, tk, eska, ska); // Run by Alice

  printf("Ok. Key exchange successful. The common secrets are:\n");
  for(i=0;i<KEX_SSBYTES;i++){
    printf("%02x", ka[i]);
  }
  printf("\n");
  for(i=0;i<KEX_SSBYTES;i++){
    printf("%02x", kb[i]);
  }
  printf("\n");

  if(!memcmp(ka,zero,KEX_SSBYTES))
    printf("Error: AKE produces zero key\n");


  printf("KEX_UAKE_SENDABYTES: %d\n",KEX_UAKE_SENDABYTES);
  printf("KEX_UAKE_SENDBBYTES: %d\n",KEX_UAKE_SENDBBYTES);

  printf("KEX_AKE_SENDABYTES: %d\n",KEX_AKE_SENDABYTES);
  printf("KEX_AKE_SENDBBYTES: %d\n",KEX_AKE_SENDBBYTES);

  return 0;
}
