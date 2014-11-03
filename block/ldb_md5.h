#ifndef _IPXE_MD5_H
#define _IPXE_MD5_H


struct digest_algorithm;

#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;

#define MD5_DIGEST_SIZE     16
#define MD5_BLOCK_WORDS     16
#define MD5_HASH_WORDS      4

struct md5_ctx {
    u32 hash[MD5_HASH_WORDS];
    u32 block[MD5_BLOCK_WORDS];
    u64 byte_count;
};

#define MD5_CTX_SIZE sizeof ( struct md5_ctx )

extern struct digest_algorithm md5_algorithm;

#endif /* _IPXE_MD5_H */

