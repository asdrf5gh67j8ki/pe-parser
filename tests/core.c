#include "ps.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static unsigned checks=0;
#define CHECK(x) do{ ++checks;if(!(x)){ fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x);return 0; } }while(0)
static void w16(uint8_t *p,uint16_t n){ p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8); }
static void fixture(uint8_t b[1536],int bits){
    unsigned optional=bits==64 ? 240u : 224u,table=0x98+optional;
    memset(b,0,1536);b[0]='M';b[1]='Z';ps_w32(b+60,0x80);memcpy(b+0x80,"PE\0\0",4);
    w16(b+0x84,(uint16_t)(bits==64 ? 0x8664 : 0x14c));w16(b+0x86,1);w16(b+0x94,(uint16_t)optional);
    w16(b+0x96,0x2022);w16(b+0x98,(uint16_t)(bits==64 ? 0x20b : 0x10b));ps_w32(b+0xa8,0x1000);
    if(bits==64){ ps_w64(b+0xb0,UINT64_C(0x180000000)); }else{ ps_w32(b+0xb4,0x400000); }
    ps_w32(b+0xb8,0x1000);ps_w32(b+0xbc,0x200);ps_w32(b+0xd0,0x3000);ps_w32(b+0xd4,0x400);
    w16(b+0xdc,3);w16(b+0xde,0x160);ps_w32(b+0x98+(bits==64 ? 108u : 92u),16);
    memcpy(b+table,".text",5);ps_w32(b+table+8,0x400);ps_w32(b+table+12,0x1000);
    ps_w32(b+table+16,0x200);ps_w32(b+table+20,0x400);ps_w32(b+table+36,0x60000020);
    b[0x400]=0xc3;
}
static void directory(uint8_t *b,int bits,unsigned index,uint32_t rva,uint32_t size){
    unsigned offset=0x98+(bits==64 ? 112u : 96u)+index*8;
    ps_w32(b+offset,rva);ps_w32(b+offset+4,size);
}
static int has(const ps_report *r,const char *kind,const char *name){
    size_t i;
    for(i=0;i<r->count;++i){ if(!strcmp(r->rows[i].kind,kind) && !strcmp(r->rows[i].name,name)){ return 1; } }
    return 0;
}
static int hashing(void){
    char hash[65];uint8_t b[1000];
    ps_sha256("",0,hash);CHECK(!strcmp(hash,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    ps_sha256("abc",3,hash);CHECK(!strcmp(hash,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    memset(b,'a',sizeof(b));ps_sha256(b,sizeof(b),hash);
    CHECK(!strcmp(hash,"41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"));
    for(unsigned i=0;i<256;++i){ b[i]=(uint8_t)i; }
    CHECK(ps_entropy(b,256)>7.999 && ps_entropy(b,256)<8.001);
    CHECK(ps_entropy(b,0)==0);CHECK(!ps_range(UINT64_MAX,2,UINT64_MAX));return 1;
}
static int mappings(void){
    uint8_t b[1536];ps_pe p;char error[256];size_t off;
    fixture(b,64);CHECK(ps_pe_parse(&p,b,sizeof(b),error,sizeof(error)));
    CHECK(p.bits==64 && p.machine==0x8664);
    CHECK(ps_pe_map(&p,0x1000,16,&off)==PS_MAP_OK && off==0x400);
    CHECK(ps_pe_map(&p,0x1200,1,&off)==PS_MAP_ZERO);
    CHECK(ps_pe_map(&p,0x5000,1,&off)==PS_MAP_MISSING);
    CHECK(ps_pe_map(&p,0x13ff,2,&off)==PS_MAP_BOUNDARY);
    CHECK(ps_pe_map(&p,UINT32_MAX,2,&off)==PS_MAP_BOUNDARY);
    p.section_count=2;p.sections[1]=p.sections[0];p.sections[1].va=0x1100;
    CHECK(ps_pe_map(&p,0x1100,1,&off)==PS_MAP_AMBIGUOUS);
    CHECK(ps_pe_map(&p,0x10ff,2,&off)==PS_MAP_AMBIGUOUS);
    fixture(b,32);CHECK(ps_pe_parse(&p,b,sizeof(b),error,sizeof(error)));CHECK(p.bits==32);
    for(size_t n=0;n<0x180;++n){ CHECK(!ps_pe_parse(&p,b,n,error,sizeof(error))); }
    ps_w32(b+60,UINT32_MAX);CHECK(!ps_pe_parse(&p,b,sizeof(b),error,sizeof(error)));return 1;
}
static int relocations(void){
    uint8_t b[1536];ps_pe p;ps_image image;char error[256];
    fixture(b,64);directory(b,64,5,0x1100,12);
    ps_w32(b+0x500,0x1000);ps_w32(b+0x504,12);w16(b+0x508,0xa040);
    ps_w64(b+0x440,UINT64_C(0x180001111));
    CHECK(ps_pe_parse(&p,b,sizeof(b),error,sizeof(error)));
    CHECK(ps_pe_image(&p,p.base+0x100000,&image,error,sizeof(error)));
    CHECK(ps_u64(image.bytes+0x1040)==p.base+0x101111);CHECK(image.relocations==1);
    CHECK(image.valid[0x1040]==3 && image.valid[0x1047]==3);
    CHECK(image.valid[0x1200]==1 && image.bytes[0x1200]==0);ps_image_free(&image);
    w16(b+0x508,0x9040);CHECK(!ps_pe_image(&p,p.base+0x100000,&image,error,sizeof(error)));
    w16(b+0x508,0xa040);w16(b+0x50a,0xa040);
    CHECK(!ps_pe_image(&p,p.base+0x100000,&image,error,sizeof(error)));
    fixture(b,32);directory(b,32,5,0x1100,12);ps_w32(b+0x500,0x1000);ps_w32(b+0x504,12);
    w16(b+0x508,0x3040);ps_w32(b+0x440,0x401111);
    CHECK(ps_pe_parse(&p,b,sizeof(b),error,sizeof(error)));
    CHECK(ps_pe_image(&p,p.base+0x200000,&image,error,sizeof(error)));
    CHECK(ps_u32(image.bytes+0x1040)==0x601111);ps_image_free(&image);
    directory(b,32,5,0,0);CHECK(ps_pe_parse(&p,b,sizeof(b),error,sizeof(error)));
    CHECK(!ps_pe_image(&p,p.base+0x1000,&image,error,sizeof(error)));return 1;
}
static int runtime_base(void){
    uint8_t file[1536],observed[1536],expected[1536];
    ps_pe p;char error[256];
    const uint64_t actual=UINT64_C(0x7ffdf6be0000);
    size_t field=0x130,changed=0;
    /* Match the reported header layout: ImageBase at 0x130, four differing
       bytes beginning at 0x132 when 0x180000000 becomes 0x7ffdf6be0000. */
    fixture(file,64);memmove(file+0x100,file+0x80,0x130);memset(file+0x80,0,0x80);
    ps_w32(file+60,0x100);
    CHECK(ps_pe_parse(&p,file,sizeof(file),error,sizeof(error)));
    CHECK(p.optional+24==field);
    memcpy(observed,file,sizeof(file));memcpy(expected,file,sizeof(file));
    CHECK(!ps_pe_runtime_base(&p,actual,0,observed,expected,sizeof(expected)));
    CHECK(!memcmp(expected,file,sizeof(file)));
    ps_w64(observed+field,actual);
    for(size_t i=0;i<sizeof(file);++i){ if(observed[i]!=expected[i]){ ++changed; } }
    CHECK(changed==4);
    CHECK(ps_pe_runtime_base(&p,actual,0,observed,expected,sizeof(expected)));
    CHECK(!memcmp(observed,expected,sizeof(expected)));
    CHECK(ps_u64(file+field)==p.base);
    for(size_t i=0;i<8;++i){
        memcpy(expected,file,sizeof(file));observed[field+i]^=1;
        CHECK(!ps_pe_runtime_base(&p,actual,0,observed,expected,sizeof(expected)));
        CHECK(!memcmp(expected,file,sizeof(file)));observed[field+i]^=1;
    }
    memcpy(expected,file,sizeof(file));observed[p.optional+16]^=1;
    CHECK(ps_pe_runtime_base(&p,actual,0,observed,expected,sizeof(expected)));
    CHECK(observed[p.optional+16]!=expected[p.optional+16]);
    observed[p.optional+16]^=1;
    for(size_t n=0;n<8;++n){
        memcpy(expected,file,sizeof(file));
        CHECK(!ps_pe_runtime_base(&p,actual,0,observed,expected,field+n));
        CHECK(!memcmp(expected,file,sizeof(file)));
    }
    CHECK(!ps_pe_runtime_base(&p,actual,field+1,observed+field+1,expected+field+1,7));
    CHECK(!ps_pe_runtime_base(&p,actual,SIZE_MAX,NULL,NULL,0));
    CHECK(ps_pe_runtime_base(&p,actual,field,observed+field,expected+field,8));
    memcpy(expected,file,sizeof(file));
    CHECK(!ps_pe_runtime_base(&p,p.base,0,observed,expected,sizeof(expected)));
    p.headers_size=(uint32_t)field+7;
    CHECK(!ps_pe_runtime_base(&p,actual,0,observed,expected,sizeof(expected)));
    p.headers_size=0x400;p.bits=32;
    CHECK(!ps_pe_runtime_base(&p,actual,0,observed,expected,sizeof(expected)));
    p.bits=64;p.machine=0xaa64;
    CHECK(!ps_pe_runtime_base(&p,actual,0,observed,expected,sizeof(expected)));
    return 1;
}
static int directories(void){
    uint8_t b[1536];ps_pe p;ps_image image;ps_report report;char error[256];
    fixture(b,64);directory(b,64,1,0x1100,40);
    ps_w32(b+0x500,0x1160);ps_w32(b+0x50c,0x1140);ps_w32(b+0x510,0x1180);
    memcpy(b+0x540,"KERNEL32.dll",13);ps_w64(b+0x560,0x11a0);ps_w64(b+0x580,0x11a0);
    memcpy(b+0x5a2,"GetTickCount",13);
    CHECK(ps_pe_parse(&p,b,sizeof(b),error,sizeof(error)));
    CHECK(ps_pe_image(&p,p.base,&image,error,sizeof(error)));
    CHECK(image.masked==8 && image.valid[0x1180]==2 && image.valid[0x1188]==1);ps_image_free(&image);
    ps_report_init(&report,"imports");ps_pe_report(&p,&report);
    CHECK(has(&report,"imports","GetTickCount"));CHECK(!report.levels[PS_SKIP]);ps_report_free(&report);
    fixture(b,64);directory(b,64,9,0x1100,40);ps_w64(b+0x518,UINT64_C(0x180001180));ps_w64(b+0x580,UINT64_C(0x180001000));
    CHECK(ps_pe_parse(&p,b,sizeof(b),error,sizeof(error)));
    ps_report_init(&report,"tls");ps_pe_report(&p,&report);CHECK(has(&report,"tls","callback"));ps_report_free(&report);
    fixture(b,64);directory(b,64,2,0x1100,64);w16(b+0x50e,1);ps_w32(b+0x514,0x80000000);
    CHECK(ps_pe_parse(&p,b,sizeof(b),error,sizeof(error)));
    ps_report_init(&report,"cycle");ps_pe_report(&p,&report);CHECK(has(&report,"resources","invalid-tree"));ps_report_free(&report);
    return 1;
}
static int diff_and_corruption(void){
    uint8_t a[1536],b[1536];ps_pe p,q;ps_report r;char error[256];
    uint32_t state=0x12345678;
    fixture(a,64);memcpy(b,a,sizeof(b));
    CHECK(ps_pe_parse(&p,a,sizeof(a),error,sizeof(error)));CHECK(ps_pe_parse(&q,b,sizeof(b),error,sizeof(error)));
    ps_report_init(&r,"identical");ps_pe_diff(&p,&q,&r);CHECK(!r.levels[PS_CHANGE]);ps_report_free(&r);
    b[0x410]=0x41;b[0x411]=0x42;
    ps_report_init(&r,"changed");ps_pe_diff(&p,&q,&r);CHECK(r.levels[PS_CHANGE]>0);ps_report_free(&r);
    for(unsigned i=0;i<2000;++i){
        memcpy(b,a,sizeof(b));
        for(unsigned j=0;j<8;++j){
            state^=state<<13;state^=state>>17;state^=state<<5;
            b[state%sizeof(b)]^=(uint8_t)(state>>24);
        }
        if(ps_pe_parse(&q,b,sizeof(b),error,sizeof(error))){
            ps_report_init(&r,"mutation");ps_pe_report(&q,&r);ps_report_free(&r);
        }
    }
    CHECK(1);return 1;
}
int main(void){
    if(!hashing() || !mappings() || !relocations() || !runtime_base() || !directories() || !diff_and_corruption()){ return 1; }
    printf("Core: %u checks and 2000 deterministic malformed-input mutations passed.\n",checks);return 0;
}
