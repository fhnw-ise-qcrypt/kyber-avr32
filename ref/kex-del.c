#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "kem.h"
#include "kex.h"
#include "kex-helper.h"

/**
 * kex-del
 * 
 * deletes all keys and temporary files
 */ 

int main(void)
{
  deleteFile("./SKA.key");
  deleteFile("./PKA.key");
  deleteFile("./PKB.key");
  deleteFile("./TK.key");
  deleteFile("./ESKA.key");
  deleteFile("./COMMON.key");
  return 0;
}


