#include "ps.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

uint16_t ps_u16(const uint8_t *p){
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}
uint32_t ps_u32(const uint8_t *p){
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
uint64_t ps_u64(const uint8_t *p){
    return (uint64_t)ps_u32(p) | (uint64_t)ps_u32(p + 4) << 32;
}
void ps_w32(uint8_t *p, uint32_t n){
    unsigned i;
    for(i = 0; i < 4; ++i){ p[i] = (uint8_t)(n >> (i * 8)); }
}
void ps_w64(uint8_t *p, uint64_t n){
    unsigned i;
    for(i = 0; i < 8; ++i){ p[i] = (uint8_t)(n >> (i * 8)); }
}
int ps_range(uint64_t start, uint64_t length, uint64_t total){
    return start <= total && length <= total - start;
}
FILE *ps_fopen(const char *path, const char *mode){
#ifdef _WIN32
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    wchar_t *wide, wm[8];
    FILE *file;
    size_t i;
    if(n <= 0){ return NULL; }
    wide = (wchar_t *)malloc((size_t)n * sizeof(*wide));
    if(!wide){ return NULL; }
    if(!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, n)){
        free(wide); return NULL;
    }
    for(i = 0; mode[i] && i < 7; ++i){ wm[i] = (wchar_t)(unsigned char)mode[i]; }
    wm[i] = 0;
    file = _wfopen(wide, wm);
    free(wide);
    return file;
#else
    return fopen(path, mode);
#endif
}
uint8_t *ps_read_file(const char *path, size_t *size, char *error, size_t cap){
    FILE *f = ps_fopen(path, "rb");
    uint8_t *data = NULL;
    long length;
    *size = 0;
    if(!f){ snprintf(error, cap, "cannot open file (errno=%d)", errno); return NULL; }
    if(fseek(f, 0, SEEK_END) || (length = ftell(f)) < 0 || (unsigned long)length > PS_FILE_LIMIT){
        snprintf(error, cap, "file size unavailable or exceeds 128 MiB"); goto done;
    }
    if(fseek(f, 0, SEEK_SET)){ snprintf(error, cap, "cannot rewind file"); goto done; }
    data = (uint8_t *)malloc(length ? (size_t)length : 1);
    if(!data){ snprintf(error, cap, "out of memory"); goto done; }
    if(fread(data, 1, (size_t)length, f) != (size_t)length || ferror(f)){
        free(data); data = NULL; snprintf(error, cap, "file changed or could not be read"); goto done;
    }
    if(fgetc(f) != EOF){ free(data); data = NULL; snprintf(error, cap, "file grew during read"); goto done; }
    *size = (size_t)length;
done:
    fclose(f);
    return data;
}
double ps_entropy(const uint8_t *data, size_t n){
    size_t frequencies[256] = {0}, i;
    double result = 0;
    if(!n){ return 0; }
    for(i = 0; i < n; ++i){ ++frequencies[data[i]]; }
    for(i = 0; i < 256; ++i){
        if(frequencies[i]){
            double p = (double)frequencies[i] / (double)n;
            result -= p * log(p) / log(2.0);
        }
    }
    return result;
}
void ps_hex(const uint8_t *p, size_t n, char *out, size_t cap){
    static const char hex[] = "0123456789abcdef";
    size_t i, take = cap ? (cap - 1) / 2 : 0;
    if(take > n){ take = n; }
    for(i = 0; i < take; ++i){ out[i * 2] = hex[p[i] >> 4]; out[i * 2 + 1] = hex[p[i] & 15]; }
    if(cap){ out[take * 2] = 0; }
}
/* SHA-256, FIPS 180-4. All arithmetic is explicitly unsigned. */
static uint32_t rotate(uint32_t v, unsigned n){ return v >> n | v << (32 - n); }
static void sha_block(uint32_t h[8], const uint8_t block[64]){
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t w[64], a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],v=h[7];
    unsigned i;
    for(i=0; i<16; ++i){
        const uint8_t *p = block + i * 4;
        w[i] = (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
    }
    for(i=16; i<64; ++i){
        uint32_t x=w[i-15], y=w[i-2];
        w[i]=w[i-16]+(rotate(x,7)^rotate(x,18)^(x>>3))+w[i-7]+(rotate(y,17)^rotate(y,19)^(y>>10));
    }
    for(i=0; i<64; ++i){
        uint32_t t=v+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t u=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c));
        v=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=v;
}
void ps_sha256(const void *input, size_t n, char out[65]){
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    const uint8_t *p=(const uint8_t *)input;
    uint8_t block[128]={0}, digest[32];
    size_t left=n, i;
    uint64_t bits=(uint64_t)n*8;
    while(left>=64){ sha_block(h,p); p+=64; left-=64; }
    if(left){ memcpy(block,p,left); }
    block[left]=0x80;
    for(i=0;i<8;++i){ block[(left<56 ? 64u : 128u)-1-i]=(uint8_t)(bits>>(8*i)); }
    sha_block(h,block);
    if(left>=56){ sha_block(h,block+64); }
    for(i=0;i<8;++i){
        digest[i*4]=(uint8_t)(h[i]>>24);digest[i*4+1]=(uint8_t)(h[i]>>16);
        digest[i*4+2]=(uint8_t)(h[i]>>8);digest[i*4+3]=(uint8_t)h[i];
    }
    ps_hex(digest,sizeof(digest),out,65);
}
