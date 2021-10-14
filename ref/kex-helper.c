#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "kem.h"
#include "kex.h"
#include "kex-helper.h"


/**
 * @brief function to read a byte string from a txt file with bytes encoded in hexadecimal
 * @note  implementation using "getline()" which is C11 standard and does not works on avr-32 
 */
/*
int readHexFile(char *filename, uint8_t *out, size_t bytes){
  if(access(filename, F_OK) == 0){
    int i;
    char * line = NULL;
    size_t len = 0;
    ssize_t read; 
    FILE *fp;
    fp = fopen(filename, "r");
    if (fp == NULL)
      exit(EXIT_FAILURE);
    read = getline(&line, &len, fp);
    if(read == -1) return -1;
    if(len < 2*bytes){
      fprintf(stderr, "[error] %s does not contain the required amout of bytes (%d/%d)\n", filename, (int)len/2, (int)bytes);
      return -2;
    }
    for(i=0;(i<(int)bytes);i++){
      char tmp[3] = {line[2*i], line[2*i+1], 0};
      out[i] = (uint8_t)strtol(tmp,NULL,16);
    }
    fclose(fp);
    free(line);
    printf("[ ok  ] read %d / %d bytes from %s\n", (int)len/2, (int)CRYPTO_SECRETKEYBYTES, filename);
  } else {
    fprintf(stderr, "[error] file: %s does not exist\n", filename);
    return -1;
  }
  return 0;
}*/

/**
 * @brief function to read a byte string from a txt file with bytes encoded in hexadecimal
 * @note  implementation using "fread()" which works on avr-32 
 * @param filename pointer to char string containing the path to the file to be read
 * @param out pointer to output array to store the bytes in
 * @param bytes number of expected bytes to be read from the file
 * */
int readHexFile(char *filename, uint8_t *out, size_t bytes){
  printf("reading\n");
  FILE *fp;
  fp = fopen(filename, "r");
  if( fp != NULL ){
    int i;
    char line[2*bytes+1];
    size_t len = 0;
    if (fp == NULL)
      exit(EXIT_FAILURE);
    len = fread(line, sizeof(char), 2*bytes, fp);
    if(len < 2*bytes){
      fprintf(stderr, "[error] %s does not contain the required amout of bytes (%d/%d)\n", filename, (int)len/2, (int)bytes);
      return -2;
    }
    for(i=0;(i<(int)bytes);i++){
      char tmp[3] = {line[2*i], line[2*i+1], 0};
      out[i] = (uint8_t)strtol(tmp,NULL,16);
    }
    fclose(fp);
    printf("[ ok  ] read %d / %d bytes from %s\n", (int)len/2, (int)bytes, filename);
  } else {
    fclose(fp);
    fprintf(stderr, "[error] file: %s does not exist\n", filename);
    return -1;
  }
  return 0;
}

/**
 * @brief creates and writes a byte array encoded in hex to a new file
 * @param filename pointer to char string containing the path to the file to be written
 * @param in pointer to input array that should be written to the file
 * @param bytes length of the input array
 * */
int writeHexFile(char *filename, uint8_t *in, size_t bytes){
  int i;
  FILE *fp;
  fp = fopen(filename, "w+");
  for(i=0;i<(int)bytes;i++){
    fprintf(fp,"%02x", in[i]);
  }
  fclose(fp);
  printf("[ ok  ] wrote %d bytes to %s\n", (int)bytes, filename);
  return 0;
}

/**
 * @param prints the content of a byte array to the stdout
 * @param title a preamble message before the array contents e.g. the array name
 * @param bytes length of the byte array to be printed
 * */
int printHexString(char *title, uint8_t *in, size_t bytes){
  int i;
  printf("%s\n", title);
  for(i=0; i<(int)bytes; i++){
    printf("%02x", in[i]);
  }
  printf("\n[%d bytes]\n", (int)bytes);
  return 0;
}

/**
 * @param read a hex byte string from console input
 * @param prompt a preamble message that asks for a user input
 * @param out pointer to output array to store the bytes in
 * @param bytes length of the input array
 * */
int readHexString(char *prompt, uint8_t *out, size_t bytes){
  printf("%s", prompt);
  int i;
  char *line = NULL;
  size_t len = 0;
  ssize_t lineSize = 0;
  len = 0;
  lineSize = 0;
  lineSize = getline(&line, &len, stdin);
  if((int)lineSize < (int)bytes*2){
    fprintf(stderr, "[error] not enough input bytes (%d/%d)\n", (int)lineSize/2, (int)bytes);
    return -1;
  }
  for(i=0;(i<(int)bytes);i++){
    char tmp[3] = {line[2*i], line[2*i+1], 0};
    out[i] = (uint8_t)strtol(tmp,NULL,16);
  }
  free(line);
  return 0;
}

/**
 * @param read a hex byte string that was passed as a command line argument
 * @param arg the part of the argv[] array that contains the bytestring
 * @param out pointer to output array to store the bytes in
 * @param bytes length of the input array
 * */
int stdinHexString(char *arg, uint8_t *out, size_t bytes){
  int i;
  if((int)strlen(arg) < (int)bytes*2){
    fprintf(stderr, "[error] provided key is too short\n");
    return -1;
  }
  for(i=0;(i<(int)bytes);i++){
    char tmp[3] = {arg[2*i], arg[2*i+1], 0};
    out[i] = (uint8_t)strtol(tmp,NULL,16);
  }
  printf("[ ok  ] read %d / %d bytes from stdin\n", (int)bytes, (int)strlen(arg));
  return 0;
}

/**
 * @brief compares two equally sized byte arrays if all of their values match
 * @param a pointer to first array
 * @param b pointer to second array
 * @param bytes length of both arrays
 * */
int verifyArrays(char* name, uint8_t *a, uint8_t *b, size_t bytes){
  if(memcmp(a,b,bytes)){
    fprintf(stderr, "[error] %s arrays do not match!\n", name);
    return -1;
  } else {
    printf("[ ok  ] %s matching.\n", name);
  }
  return 0;
}

/**
 * @brief deletes a file 
 * */
int deleteFile(char *filename){
  if( access(filename, F_OK ) == 0 ) {
    if (remove(filename) == 0){
      printf("[ ok  ] rm %s\n", filename);
    } else {
      printf("[error] removing %s\n", filename);
    }
  } 
  return 0;
}
