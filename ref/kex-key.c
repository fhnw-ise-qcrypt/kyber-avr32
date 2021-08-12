#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "kem.h"
#include "kex.h"


/**
 * kex-key
 * 
 * displays the common shared key 
 */

int main()
{
  if( access("./COMMON.key", F_OK ) == 0 ) {
    char * line = NULL;
    size_t len = 0;
    ssize_t read; 
    FILE * fp;

    fp = fopen("./COMMON.key", "r");
    if (fp == NULL)
      exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1) {
      printf("OK: The shared key is:\n");
      printf("%s", line);
      printf("\n");
      fclose(fp);
    }
  } else {
    printf("error: there is no shared key.\n");
    return -1;
  }
  return 0;
}
