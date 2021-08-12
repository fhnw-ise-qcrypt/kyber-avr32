#ifndef KEX_HELPER_H
#define KEX_HELPER_H

int readHexFile(char *, uint8_t *, size_t);
int writeHexFile(char *, uint8_t *, size_t);
int printHexString(char *, uint8_t *, size_t);
int readHexString(char *, uint8_t *, size_t);
int stdinHexString(char*, uint8_t *, size_t);
int verifyArrays(char *, uint8_t *, uint8_t *, size_t);
int deleteFile(char *);

#endif // KEX_HELPER_H
