#include "ps.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static int fail(char *out, size_t cap, const char *reason){
    snprintf(out,cap,"%s",reason); return 0;
}
static uint64_t span(const ps_section *s){
    return s->virtual_size > s->raw_size ? s->virtual_size : s->raw_size;
}
static int overlap(uint64_t a, uint64_t n, uint64_t b, uint64_t m){
    return n && m && a < b+m && b < a+n;
}
int ps_pe_parse(ps_pe *p, const uint8_t *data, size_t size, char *error, size_t cap){
    uint32_t nt, count, directory;
    uint16_t opt, magic;
    unsigned i;
    memset(p,0,sizeof(*p));
    if(size>PS_FILE_LIMIT){ return fail(error,cap,"file exceeds 128 MiB"); }
    if(size<64 || data[0]!='M' || data[1]!='Z'){ return fail(error,cap,"missing or truncated DOS header"); }
    nt=ps_u32(data+60);
    if(!ps_range(nt,24,size) || memcmp(data+nt,"PE\0\0",4)){ return fail(error,cap,"invalid PE signature offset"); }
    opt=ps_u16(data+nt+20);
    if(!ps_range((uint64_t)nt+24,opt,size) || opt<96){ return fail(error,cap,"truncated optional header"); }
    p->data=data; p->size=size; p->nt=nt; p->optional=nt+24;
    magic=ps_u16(data+p->optional);
    if(magic!=0x10b && magic!=0x20b){ return fail(error,cap,"unsupported optional-header magic"); }
    p->bits=magic==0x20b ? 64 : 32;
    directory=p->bits==64 ? 112u : 96u;
    if(opt<directory){ return fail(error,cap,"truncated PE32+ optional header"); }
    p->machine=ps_u16(data+nt+4);
    p->section_count=ps_u16(data+nt+6);
    p->timestamp=ps_u32(data+nt+8);
    p->characteristics=ps_u16(data+nt+22);
    p->entry=ps_u32(data+p->optional+16);
    p->base=p->bits==64 ? ps_u64(data+p->optional+24) : ps_u32(data+p->optional+28);
    p->section_alignment=ps_u32(data+p->optional+32);
    p->file_alignment=ps_u32(data+p->optional+36);
    p->image_size=ps_u32(data+p->optional+56);
    p->headers_size=ps_u32(data+p->optional+60);
    p->checksum=ps_u32(data+p->optional+64);
    p->subsystem=ps_u16(data+p->optional+68);
    p->dll_flags=ps_u16(data+p->optional+70);
    count=ps_u32(data+p->optional+directory-4);
    if(count>16){ return fail(error,cap,"more than 16 data directories are unsupported"); }
    if(!ps_range(directory,(uint64_t)count*8,opt)){ return fail(error,cap,"data directories exceed optional header"); }
    for(i=0;i<count;++i){
        p->dirs[i].address=ps_u32(data+p->optional+directory+i*8);
        p->dirs[i].size=ps_u32(data+p->optional+directory+i*8+4);
    }
    p->section_table=p->optional+opt;
    if(!p->section_count || p->section_count>PS_SECTIONS ||
       !ps_range(p->section_table,(uint64_t)p->section_count*40,size)){
        return fail(error,cap,"invalid/truncated section table (supported: 1..96 sections)");
    }
    for(i=0;i<p->section_count;++i){
        ps_section *s=&p->sections[i];
        const uint8_t *h=data+p->section_table+i*40;
        memcpy(s->name,h,8); s->name[8]=0;
        s->header=p->section_table+i*40;
        s->virtual_size=ps_u32(h+8); s->va=ps_u32(h+12);
        s->raw_size=ps_u32(h+16); s->raw=ps_u32(h+20); s->flags=ps_u32(h+36);
    }
    return 1;
}
ps_mapping ps_pe_map(const ps_pe *p, uint32_t rva, size_t n, size_t *offset){
    const ps_section *found=NULL;
    unsigned i, hits=0;
    int headers=0;
    uint64_t length=n ? n : 1;
    if(!ps_range(rva,length,UINT64_C(0x100000000))){ return PS_MAP_BOUNDARY; }
    if(overlap(rva,length,0,p->headers_size)){ ++hits; headers=1; }
    for(i=0;i<p->section_count;++i){
        if(overlap(rva,length,p->sections[i].va,span(&p->sections[i]))){ ++hits; found=&p->sections[i]; }
    }
    if(hits>1){ return PS_MAP_AMBIGUOUS; }
    if(!hits){ return PS_MAP_MISSING; }
    if(headers){
        if(!ps_range(rva,length,p->headers_size)){ return PS_MAP_BOUNDARY; }
        if(!ps_range(rva,length,p->size)){ return PS_MAP_TRUNCATED; }
        *offset=rva; return PS_MAP_OK;
    }
    if(rva<found->va || !ps_range(rva-found->va,length,span(found))){ return PS_MAP_BOUNDARY; }
    if(!ps_range(rva-found->va,length,found->raw_size)){ return PS_MAP_ZERO; }
    if(!ps_range((uint64_t)found->raw+rva-found->va,length,p->size)){ return PS_MAP_TRUNCATED; }
    *offset=(size_t)((uint64_t)found->raw+rva-found->va); return PS_MAP_OK;
}
const char *ps_mapping_name(ps_mapping m){
    static const char *names[]={"file-backed","zero-fill","unmapped","ambiguous","truncated","crosses-boundary"};
    return names[(unsigned)m<6 ? m : PS_MAP_MISSING];
}
const ps_section *ps_pe_section(const ps_pe *p, uint32_t rva){
    const ps_section *found=NULL;
    unsigned i;
    for(i=0;i<p->section_count;++i){
        if(rva>=p->sections[i].va && rva-p->sections[i].va<span(&p->sections[i])){
            if(found){ return NULL; }
            found=&p->sections[i];
        }
    }
    return found;
}
static int string_at(const ps_pe *p, uint32_t rva, char *out, size_t cap){
    size_t off,again,n;
    const uint8_t *end;
    if(!cap || ps_pe_map(p,rva,1,&off)!=PS_MAP_OK){ return 0; }
    n=p->size-off<cap ? p->size-off : cap;
    end=(const uint8_t *)memchr(p->data+off,0,n);
    if(!end){ return 0; }
    n=(size_t)(end-(p->data+off))+1;
    if(ps_pe_map(p,rva,n,&again)!=PS_MAP_OK || again!=off){ return 0; }
    memcpy(out,p->data+off,n);return 1;
}
static uint32_t relative(const ps_pe *p, uint32_t value, int is_rva){
    if(is_rva){ return value; }
    return value>=p->base && value-p->base<=UINT32_MAX ? (uint32_t)(value-p->base) : 0;
}
int ps_pe_imports(const ps_pe *p, ps_import_fn callback, void *context, char *error, size_t cap){
    unsigned which;
    size_t total=0;
    for(which=0;which<2;++which){
        const ps_directory *d=&p->dirs[which ? 13 : 1];
        uint32_t step=which ? 32u : 20u, pos;
        int terminated=0;
        if(!d->address && !d->size){ continue; }
        if(!d->address || d->size<step){ return fail(error,cap,"invalid import directory"); }
        for(pos=0;ps_range(pos,step,d->size);pos+=step){
            size_t off, i;
            const uint8_t *desc;
            uint32_t name, table, iat;
            char dll[4096];
            int zero=1;
            if(++total>PS_ITEM_LIMIT){ return fail(error,cap,"import item limit reached"); }
            if(!ps_range(d->address,(uint64_t)pos+step,UINT64_C(0x100000000)) ||
               ps_pe_map(p,d->address+pos,step,&off)!=PS_MAP_OK){ return fail(error,cap,"unreadable import descriptor"); }
            desc=p->data+off;
            for(i=0;i<step;++i){ if(desc[i]){ zero=0; break; } }
            if(zero){ terminated=1; break; }
            if(which){
                int is_rva=(ps_u32(desc)&1)!=0;
                name=relative(p,ps_u32(desc+4),is_rva);
                iat=relative(p,ps_u32(desc+12),is_rva);
                table=relative(p,ps_u32(desc+16),is_rva);
            }else{
                table=ps_u32(desc); name=ps_u32(desc+12); iat=ps_u32(desc+16);
            }
            if(!table){ table=iat; }
            if(!name || !iat || !table || !string_at(p,name,dll,sizeof(dll))){
                return fail(error,cap,"invalid import name/table");
            }
            for(i=0;i<PS_ITEM_LIMIT;++i){
                size_t width=(size_t)p->bits/8, entryoff;
                uint64_t delta=(uint64_t)i*width, value;
                char symbol[4096];
                if(++total>PS_ITEM_LIMIT){ return fail(error,cap,"import item limit reached"); }
                if(!ps_range(table,delta+width,UINT64_C(0x100000000)) ||
                   !ps_range(iat,delta+width,UINT64_C(0x100000000)) ||
                   ps_pe_map(p,table+(uint32_t)delta,width,&entryoff)!=PS_MAP_OK){
                    return fail(error,cap,"unterminated or unreadable import thunk table");
                }
                value=width==8 ? ps_u64(p->data+entryoff) : ps_u32(p->data+entryoff);
                if(!value){ break; }
                if(value&(UINT64_C(1)<<(p->bits-1))){
                    snprintf(symbol,sizeof(symbol),"ordinal:%u",(unsigned)(value&0xffff));
                }else if(value>UINT32_MAX-2 || !string_at(p,(uint32_t)value+2,symbol,sizeof(symbol))){
                    snprintf(symbol,sizeof(symbol),"unresolved-name:0x%" PRIx64,value);
                }
                if(ps_pe_map(p,iat+(uint32_t)delta,width,&entryoff)!=PS_MAP_OK){
                    return fail(error,cap,"import address slot is not file-backed");
                }
                if(!callback(context,dll,symbol,iat+(uint32_t)delta,(int)which)){
                    return fail(error,cap,"import callback stopped");
                }
            }
        }
        if(!terminated){ return fail(error,cap,"import descriptor list has no terminator"); }
    }
    return 1;
}
typedef struct { const ps_pe *p; ps_report *r; } pe_report_context;
static int report_import(void *context,const char *dll,const char *name,uint32_t slot,int delay){
    pe_report_context *c=(pe_report_context *)context;
    size_t offset=0;
    (void)ps_pe_map(c->p,slot,(size_t)c->p->bits/8,&offset);
    ps_emit(c->r,"imports",PS_INFO,name,slot,(uint64_t)c->p->bits/8,
            "dll=%s | %s | slot RVA=0x%08" PRIx32 " file=0x%zx",dll,delay ? "delay" : "normal",slot,offset);
    return !c->r->limited;
}
static void report_exports(const ps_pe *p,ps_report *r){
    const ps_directory *d=&p->dirs[0];
    size_t off, functions, names, ordinals;
    uint32_t base,nf,nn,i;
    uint8_t *named;
    if(!d->address && !d->size){ return; }
    if(d->size<40 || ps_pe_map(p,d->address,40,&off)!=PS_MAP_OK){ goto invalid; }
    base=ps_u32(p->data+off+16); nf=ps_u32(p->data+off+20); nn=ps_u32(p->data+off+24);
    if(nf>PS_ITEM_LIMIT || nn>PS_ITEM_LIMIT){ goto invalid; }
    if(!nf){ return; }
    if(ps_pe_map(p,ps_u32(p->data+off+28),(size_t)nf*4,&functions)!=PS_MAP_OK){ goto invalid; }
    names=ordinals=0;
    if(nn && (ps_pe_map(p,ps_u32(p->data+off+32),(size_t)nn*4,&names)!=PS_MAP_OK ||
              ps_pe_map(p,ps_u32(p->data+off+36),(size_t)nn*2,&ordinals)!=PS_MAP_OK)){ goto invalid; }
    named=(uint8_t *)calloc(nf,1);
    if(!named){ ps_emit(r,"exports",PS_ERROR,"allocation",0,0,"out of memory"); return; }
    for(i=0;i<nn+nf && !r->limited;++i){
        uint32_t index;
        uint32_t target;
        char name[4096], forward[4096]="";
        if(i<nn){
            index=ps_u16(p->data+ordinals+(size_t)i*2);
            if(index>=nf || !string_at(p,ps_u32(p->data+names+(size_t)i*4),name,sizeof(name))){
                free(named); goto invalid;
            }
            named[index]=1;
        }else{
            index=i-nn;
            if(named[index]){ continue; }
            snprintf(name,sizeof(name),"ordinal:%" PRIu64,(uint64_t)base+index);
        }
        target=ps_u32(p->data+functions+(size_t)index*4);
        if(!target){ continue; }
        if(target>=d->address && (uint64_t)target-d->address<d->size){
            if(!string_at(p,target,forward,sizeof(forward))){ free(named); goto invalid; }
        }
        ps_emit(r,"exports",PS_INFO,name,target,0,"ordinal=%" PRIu64 " | %s%s",
                (uint64_t)base+index,forward[0] ? "forwarder=" : "target RVA",forward);
    }
    free(named); return;
invalid:
    ps_emit(r,"exports",PS_SKIP,"malformed",d->address,d->size,"export table is truncated, ambiguous, or exceeds limits");
}
static void resource_tree(const ps_pe *p,ps_report *r,size_t root,uint32_t length,uint32_t node,
                          uint32_t stack[16],unsigned depth,const char *prefix,unsigned *budget){
    const uint8_t *q;
    unsigned count,i;
    if(depth>=16 || !ps_range(node,16,length)){ goto invalid; }
    for(i=0;i<depth;++i){ if(stack[i]==node){ goto invalid; } }
    stack[depth]=node; q=p->data+root+node;
    count=(unsigned)ps_u16(q+12)+ps_u16(q+14);
    if(!ps_range((uint64_t)node+16,(uint64_t)count*8,length)){ goto invalid; }
    for(i=0;i<count && !r->limited;++i){
        const uint8_t *e=q+16+i*8;
        uint32_t id=ps_u32(e), child=ps_u32(e+4);
        char label[192], path[1024];
        int written;
        if(++*budget>PS_ITEM_LIMIT){ goto invalid; }
        if(id&0x80000000u){
            uint32_t where=id&0x7fffffffu;
            unsigned n,j;
            size_t used=0;
            if(!ps_range(where,2,length)){ goto invalid; }
            n=ps_u16(p->data+root+where);
            if(n>30 || !ps_range((uint64_t)where+2,(uint64_t)n*2,length)){
                snprintf(label,sizeof(label),"name@0x%08" PRIx32,id&0x7fffffffu);
            }else{
                for(j=0;j<n;++j){
                    unsigned ch=ps_u16(p->data+root+where+2+j*2);
                    if(ch>=32 && ch<127){ label[used++]=(char)ch; }
                    else{ used+=(size_t)snprintf(label+used,sizeof(label)-used,"\\u%04x",ch); }
                }
                label[used]=0;
            }
        }else{ snprintf(label,sizeof(label),"%" PRIu32,id); }
        written=snprintf(path,sizeof(path),"%s%s%s",prefix,*prefix ? "/" : "",label);
        if(written<0 || (size_t)written>=sizeof(path)){ goto invalid; }
        if(child&0x80000000u){
            resource_tree(p,r,root,length,child&0x7fffffffu,stack,depth+1,path,budget);
        }else{
            uint32_t data_rva,n,codepage;
            size_t offset=0;
            ps_mapping m;
            if(!ps_range(child,16,length)){ goto invalid; }
            data_rva=ps_u32(p->data+root+child); n=ps_u32(p->data+root+child+4);
            codepage=ps_u32(p->data+root+child+8); m=ps_pe_map(p,data_rva,n,&offset);
            ps_emit(r,"resources",m==PS_MAP_OK ? PS_INFO : PS_SKIP,path,data_rva,n,
                    "%s | file=0x%zx | codepage=%" PRIu32,ps_mapping_name(m),offset,codepage);
        }
    }
    return;
invalid:
    ps_emit(r,"resources",PS_SKIP,"invalid-tree",node,0,"resource bounds, cycle, depth, or item limit reached");
}
static void report_tls(const ps_pe *p,ps_report *r){
    const ps_directory *d=&p->dirs[9];
    size_t off,i,width=(size_t)p->bits/8;
    uint64_t callbacks;
    if(!d->address && !d->size){ return; }
    if(d->size<(p->bits==64 ? 40u : 24u) || ps_pe_map(p,d->address,p->bits==64 ? 40u : 24u,&off)!=PS_MAP_OK){ goto invalid; }
    callbacks=width==8 ? ps_u64(p->data+off+24) : ps_u32(p->data+off+12);
    if(!callbacks){ return; }
    if(callbacks<p->base || callbacks-p->base>UINT32_MAX){ goto invalid; }
    for(i=0;i<PS_ITEM_LIMIT && !r->limited;++i){
        uint64_t at=callbacks-p->base+(uint64_t)i*(uint64_t)width, target;
        const ps_section *s;
        size_t targetoff=0;
        ps_mapping m;
        if(at>UINT32_MAX || ps_pe_map(p,(uint32_t)at,width,&off)!=PS_MAP_OK){ goto invalid; }
        target=width==8 ? ps_u64(p->data+off) : ps_u32(p->data+off);
        if(!target){ return; }
        if(target<p->base || target-p->base>UINT32_MAX){ goto invalid; }
        s=ps_pe_section(p,(uint32_t)(target-p->base));
        m=ps_pe_map(p,(uint32_t)(target-p->base),1,&targetoff);
        ps_emit(r,"tls",m==PS_MAP_OK && s && (s->flags&0x20000000u) ? PS_INFO : PS_WARN,
                "callback",target,width,"index=%zu | section=%s | RVA=0x%" PRIx64 " | file=0x%zx | %s",
                i,s ? s->name : "unresolved",target-p->base,targetoff,ps_mapping_name(m));
    }
invalid:
    ps_emit(r,"tls",PS_SKIP,"malformed",d->address,d->size,"TLS callbacks could not be fully resolved");
}
static void report_relocs(const ps_pe *p,ps_report *r){
    const ps_directory *d=&p->dirs[5];
    uint32_t pos=0;
    size_t total=0;
    if(!d->address && !d->size){ return; }
    while(pos<d->size && !r->limited){
        size_t off,i;
        uint32_t page,block;
        if(!ps_range(d->address,(uint64_t)pos+8,UINT64_C(0x100000000)) ||
           !ps_range(pos,8,d->size) || ps_pe_map(p,d->address+pos,8,&off)!=PS_MAP_OK){ goto invalid; }
        page=ps_u32(p->data+off); block=ps_u32(p->data+off+4);
        if(block<8 || block%2 || !ps_range(pos,block,d->size) ||
           ps_pe_map(p,d->address+pos,block,&off)!=PS_MAP_OK){ goto invalid; }
        for(i=8;i<block;i+=2){
            unsigned v=ps_u16(p->data+off+i), type=v>>12;
            uint64_t at=(uint64_t)page+(v&4095u);
            if(++total>PS_ITEM_LIMIT){ goto invalid; }
            if(type){ ps_emit(r,"relocations",PS_INFO,type==10 ? "DIR64" : type==3 ? "HIGHLOW" : "other",
                             at,type==10 ? 8u : type==3 ? 4u : 0u,"type=%u | block RVA=0x%08" PRIx32,type,page); }
        }
        pos+=block;
    }
    return;
invalid:
    ps_emit(r,"relocations",PS_SKIP,"malformed",d->address,d->size,"invalid relocation block or item limit reached");
}
static int compare_u64(const void *a,const void *b){
    uint64_t x=*(const uint64_t *)a,y=*(const uint64_t *)b; return (x>y)-(x<y);
}
static void report_header_fields(const ps_pe *p,ps_report *r){
    static const struct { const char *name; unsigned offset,width; } fields[]={
        {"Magic",0,2},{"MajorLinkerVersion",2,1},{"MinorLinkerVersion",3,1},
        {"SizeOfCode",4,4},{"SizeOfInitializedData",8,4},{"SizeOfUninitializedData",12,4},
        {"AddressOfEntryPoint",16,4},{"BaseOfCode",20,4},{"SectionAlignment",32,4},{"FileAlignment",36,4},
        {"MajorOperatingSystemVersion",40,2},{"MinorOperatingSystemVersion",42,2},
        {"MajorImageVersion",44,2},{"MinorImageVersion",46,2},
        {"MajorSubsystemVersion",48,2},{"MinorSubsystemVersion",50,2},
        {"Win32VersionValue",52,4},{"SizeOfImage",56,4},{"SizeOfHeaders",60,4},
        {"CheckSum",64,4},{"Subsystem",68,2},{"DllCharacteristics",70,2}
    };
    static const char *sizes[]={"SizeOfStackReserve","SizeOfStackCommit","SizeOfHeapReserve","SizeOfHeapCommit"};
    unsigned i,width=p->bits==64 ? 8u : 4u;
    ps_emit(r,"headers",PS_INFO,"e_lfanew",60,4,"0x%08" PRIx32,p->nt);
    ps_emit(r,"headers",PS_INFO,"COFF.Characteristics",p->nt+22,2,"0x%04x",p->characteristics);
    ps_emit(r,"headers",PS_INFO,"COFF.SymbolTable",p->nt+12,8,"file=0x%08" PRIx32 " | symbols=%" PRIu32,
            ps_u32(p->data+p->nt+12),ps_u32(p->data+p->nt+16));
    for(i=0;i<sizeof(fields)/sizeof(*fields);++i){
        const uint8_t *q=p->data+p->optional+fields[i].offset;
        uint64_t value=fields[i].width==4 ? ps_u32(q) : fields[i].width==2 ? ps_u16(q) : q[0];
        ps_emit(r,"headers",PS_INFO,fields[i].name,p->optional+fields[i].offset,fields[i].width,
                "0x%" PRIx64 " (%" PRIu64 ")",value,value);
    }
    if(p->bits==32){
        ps_emit(r,"headers",PS_INFO,"BaseOfData",p->optional+24,4,"0x%08" PRIx32,ps_u32(p->data+p->optional+24));
    }
    ps_emit(r,"headers",PS_INFO,"ImageBase",p->optional+(p->bits==64 ? 24u : 28u),width,"0x%016" PRIx64,p->base);
    for(i=0;i<4;++i){
        unsigned offset=72+i*width;
        uint64_t value=width==8 ? ps_u64(p->data+p->optional+offset) : ps_u32(p->data+p->optional+offset);
        ps_emit(r,"headers",PS_INFO,sizes[i],p->optional+offset,width,"0x%" PRIx64 " (%" PRIu64 ")",value,value);
    }
    ps_emit(r,"headers",PS_INFO,"LoaderFlags",p->optional+72+width*4,4,"0x%08" PRIx32,ps_u32(p->data+p->optional+72+width*4));
    ps_emit(r,"headers",PS_INFO,"NumberOfRvaAndSizes",p->optional+76+width*4,4,"%" PRIu32,ps_u32(p->data+p->optional+76+width*4));
}
static void report_debug_and_exceptions(const ps_pe *p,ps_report *r){
    const ps_directory *d=&p->dirs[6];
    size_t off;
    uint32_t pos;
    if(d->size){
        if(d->size%28 || d->size/28>PS_ITEM_LIMIT || ps_pe_map(p,d->address,d->size,&off)!=PS_MAP_OK){
            ps_emit(r,"debug",PS_SKIP,"malformed",d->address,d->size,"debug directory unavailable");
        }else{
            for(pos=0;pos<d->size && !r->limited;pos+=28){
                const uint8_t *q=p->data+off+pos;
                uint32_t type=ps_u32(q+12),size=ps_u32(q+16),raw=ps_u32(q+24);
                ps_emit(r,"debug",PS_INFO,"entry",raw,size,"type=%" PRIu32 " | RVA=0x%08" PRIx32,type,ps_u32(q+20));
                if(type==2 && size>=25 && ps_range(raw,size,p->size) && !memcmp(p->data+raw,"RSDS",4)){
                    const uint8_t *path=p->data+raw+24;
                    const uint8_t *end=(const uint8_t *)memchr(path,0,size-24<4096 ? size-24 : 4096);
                    char guid[33];
                    if(!end){ ps_emit(r,"debug",PS_SKIP,"PDB",raw,size,"unterminated or oversized PDB path");continue; }
                    ps_hex(p->data+raw+4,16,guid,sizeof(guid));
                    ps_emit(r,"debug",PS_INFO,"PDB",raw,size,"path=%s | GUID bytes=%s | age=%" PRIu32,
                            (const char *)path,guid,ps_u32(p->data+raw+20));
                }
            }
        }
    }
    d=&p->dirs[3];
    if(p->machine==0x8664 && d->size){
        if(d->size%12 || d->size/12>PS_ITEM_LIMIT || ps_pe_map(p,d->address,d->size,&off)!=PS_MAP_OK){
            ps_emit(r,"exceptions",PS_SKIP,"malformed",d->address,d->size,"AMD64 runtime-function table unavailable");return;
        }
        for(pos=0;pos<d->size && !r->limited;pos+=12){
            const uint8_t *q=p->data+off+pos;
            uint32_t begin=ps_u32(q),end=ps_u32(q+4),unwind=ps_u32(q+8);
            if(!begin && !end && !unwind){ continue; }
            ps_emit(r,"exceptions",end>begin && end<=p->image_size ? PS_INFO : PS_WARN,"RUNTIME_FUNCTION",
                    begin,end>=begin ? end-begin : 0,"end RVA=0x%08" PRIx32 " | unwind RVA=0x%08" PRIx32,end,unwind);
        }
    }
}
void ps_pe_report(const ps_pe *p,ps_report *r){
    static const char *directories[16]={"exports","imports","resources","exceptions","certificates","relocations",
        "debug","architecture","global-pointer","tls","load-config","bound-imports","iat","delay-imports","clr","reserved"};
    char hash[65],error[256];
    uint64_t boundaries[2*PS_SECTIONS+6], end=0;
    size_t points=0,off=0,i,j;
    pe_report_context context={p,r};
    ps_mapping m;
    ps_sha256(p->data,p->size,hash);
    ps_emit(r,"identity",PS_INFO,"SHA-256",0,p->size,"%s",hash);
    report_header_fields(p,r);
    ps_emit(r,"headers",PS_INFO,"image",p->base,p->image_size,
            "PE%d | machine=0x%04x | sections=%u | subsystem=%u | timestamp=0x%08" PRIx32 " | checksum=0x%08" PRIx32,
            p->bits,p->machine,p->section_count,p->subsystem,p->timestamp,p->checksum);
    ps_emit(r,"headers",PS_INFO,"mitigation-flags",p->optional+70,2,
            "ASLR=%s | high-entropy-VA=%s | NX=%s | CFG=%s | declared flags=0x%04x; runtime enforcement not assessed",
            p->dll_flags&0x40 ? "yes" : "no",p->dll_flags&0x20 ? "yes" : "no",
            p->dll_flags&0x100 ? "yes" : "no",p->dll_flags&0x4000 ? "yes" : "no",p->dll_flags);
    ps_emit(r,"headers",PS_INFO,"alignment",p->optional+32,8,"section=0x%" PRIx32 " | file=0x%" PRIx32,
            p->section_alignment,p->file_alignment);
    if(!p->file_alignment || (p->file_alignment&(p->file_alignment-1)) ||
       !p->section_alignment || (p->section_alignment&(p->section_alignment-1))){
        ps_emit(r,"findings",PS_WARN,"alignment.invalid",p->optional+32,8,"alignment is zero or not a power of two");
    }
    if(p->headers_size<p->section_table+(uint32_t)p->section_count*40 || p->headers_size>p->size){
        ps_emit(r,"findings",PS_WARN,"headers.size",p->optional+60,4,"declared headers do not contain the table or exceed the file");
    }
    m=ps_pe_map(p,p->entry,1,&off);
    if(p->entry){
        const ps_section *s=ps_pe_section(p,p->entry);
        ps_emit(r,"entry",m==PS_MAP_OK && s && (s->flags&0x20000000u) ? PS_INFO : PS_WARN,"entry-point",
                p->entry,0,"section=%s | file=0x%zx | %s",s ? s->name : "unresolved",off,ps_mapping_name(m));
    }else{ ps_emit(r,"entry",PS_INFO,"entry-point",0,0,"no entry point declared"); }
    boundaries[points++]=0; boundaries[points++]=p->size;
    if(p->headers_size<=p->size){ boundaries[points++]=p->headers_size; end=p->headers_size; }
    for(i=0;i<p->section_count;++i){
        const ps_section *s=&p->sections[i];
        int valid=ps_range(s->raw,s->raw_size,p->size);
        size_t sample=s->raw_size<1048576u ? s->raw_size : 1048576u;
        double entropy=valid ? ps_entropy(p->data+s->raw,sample) : 0;
        ps_emit(r,"sections",valid ? PS_INFO : PS_WARN,s->name,s->va,span(s),
                "%c%c%c | raw=0x%08" PRIx32 "+0x%08" PRIx32 " | virtual=0x%08" PRIx32
                " | entropy=%.3f/%zu bytes | flags=0x%08" PRIx32 " | header=0x%08" PRIx32,
                s->flags&0x40000000u ? 'R' : '-',s->flags&0x80000000u ? 'W' : '-',
                s->flags&0x20000000u ? 'X' : '-',s->raw,s->raw_size,s->virtual_size,entropy,sample,s->flags,s->header);
        if(valid && s->raw_size){
            boundaries[points++]=s->raw; boundaries[points++]=(uint64_t)s->raw+s->raw_size;
            if(end<(uint64_t)s->raw+s->raw_size){ end=(uint64_t)s->raw+s->raw_size; }
        }
        if(!ps_range(s->va,span(s),p->image_size)){
            ps_emit(r,"findings",PS_WARN,"section.image-range",s->header+8,12,"%s exceeds SizeOfImage",s->name);
        }
        if((s->flags&0xa0000000u)==0xa0000000u){
            ps_emit(r,"findings",PS_WARN,"section.writable-executable",s->va,span(s),"%s declares write and execute",s->name);
        }
        if(valid && sample>=4096 && entropy>7.4 && (s->flags&0x20000000u)){
            ps_emit(r,"findings",PS_WARN,"packing.indicator",s->raw,sample,
                    "%s has high-entropy executable data; compression/encryption indicator, not a packer identification",s->name);
        }
        for(j=0;j<i;++j){
            if(overlap(s->va,span(s),p->sections[j].va,span(&p->sections[j])) ||
               overlap(s->raw,s->raw_size,p->sections[j].raw,p->sections[j].raw_size)){
                ps_emit(r,"findings",PS_WARN,"sections.overlap",s->header,40,"%s overlaps %s in declared virtual or raw ranges",s->name,p->sections[j].name);
            }
        }
    }
    for(i=0;i<16;++i){
        const ps_directory *d=&p->dirs[i];
        if(!d->address && !d->size){ continue; }
        off=0;
        m=i==4 ? (ps_range(d->address,d->size,p->size) ? PS_MAP_OK : PS_MAP_TRUNCATED) :
                 ps_pe_map(p,d->address,d->size,&off);
        if(i==4){ off=d->address; }
        ps_emit(r,"directories",m==PS_MAP_OK ? PS_INFO : PS_SKIP,directories[i],d->address,d->size,
                "%s | file=0x%zx%s",ps_mapping_name(m),off,i==4 ? " | certificate presence does not verify trust" : "");
    }
    if(p->dirs[4].size && ps_range(p->dirs[4].address,p->dirs[4].size,p->size)){
        uint64_t at=p->dirs[4].address,stop=at+p->dirs[4].size;
        boundaries[points++]=at; boundaries[points++]=stop;
        while(at<stop && !r->limited){
            uint32_t n;
            if(!ps_range(at,8,stop) || (n=ps_u32(p->data+(size_t)at))<8 || !ps_range(at,n,stop)){
                ps_emit(r,"certificates",PS_SKIP,"malformed",at,stop-at,"invalid WIN_CERTIFICATE length"); break;
            }
            ps_emit(r,"certificates",PS_INFO,"WIN_CERTIFICATE",at,n,"revision=0x%04x | type=0x%04x | trust=not-verified",
                    ps_u16(p->data+(size_t)at+4),ps_u16(p->data+(size_t)at+6));
            at+=((uint64_t)n+7)&~UINT64_C(7);
            if(at>stop){ ps_emit(r,"certificates",PS_SKIP,"alignment",at,0,"certificate padding exceeds directory"); }
        }
    }
    qsort(boundaries,points,sizeof(*boundaries),compare_u64);
    for(i=1;i<points;++i){
        uint64_t a=boundaries[i-1],b=boundaries[i];
        unsigned owners=0;
        const char *owner="gap";
        if(a==b){ continue; }
        if(a<p->headers_size){ owner="headers"; ++owners; }
        for(j=0;j<p->section_count;++j){
            const ps_section *s=&p->sections[j];
            if(a>=s->raw && b<=(uint64_t)s->raw+s->raw_size){ owner=s->name; ++owners; }
        }
        if(p->dirs[4].size && a>=p->dirs[4].address && b<=(uint64_t)p->dirs[4].address+p->dirs[4].size){
            owner="certificate-data"; ++owners;
        }
        if(!owners && a>=end){ owner="trailing-data"; }
        ps_emit(r,"coverage",owners>1 ? PS_WARN : PS_INFO,owners>1 ? "overlap" : owner,a,b-a,
                "file range [0x%" PRIx64 ",0x%" PRIx64 ") | claims=%u",a,b,owners);
    }
    if(!ps_pe_imports(p,report_import,&context,error,sizeof(error))){
        ps_emit(r,"imports",PS_SKIP,"incomplete",0,0,"%s",error);
    }
    report_exports(p,r); report_tls(p,r); report_relocs(p,r);report_debug_and_exceptions(p,r);
    if(p->dirs[2].size){
        uint32_t stack[16]; unsigned budget=0;
        if(ps_pe_map(p,p->dirs[2].address,p->dirs[2].size,&off)==PS_MAP_OK){
            resource_tree(p,r,off,p->dirs[2].size,0,stack,0,"",&budget);
        }
    }
}
typedef struct { ps_image *image; size_t width; } mask_context;
static int mask_import(void *context,const char *dll,const char *name,uint32_t slot,int delay){
    mask_context *c=(mask_context *)context;
    size_t i;
    (void)dll;(void)name;(void)delay;
    if(!ps_range(slot,c->width,c->image->size)){ return 0; }
    for(i=0;i<c->width;++i){
        if(c->image->valid[slot+i]==1 || c->image->valid[slot+i]==3){ c->image->valid[slot+i]=2; ++c->image->masked; }
    }
    return 1;
}
void ps_image_free(ps_image *image){
    free(image->bytes); free(image->valid); memset(image,0,sizeof(*image));
}
int ps_pe_image(const ps_pe *p,uint64_t actual,ps_image *image,char *error,size_t cap){
    unsigned i,visited=0;
    uint32_t pos=0;
    uint64_t delta=actual-p->base;
    const ps_directory *d=&p->dirs[5];
    mask_context mask;
    memset(image,0,sizeof(*image));
    if(!p->image_size || p->image_size>PS_IMAGE_LIMIT || p->headers_size>p->size ||
       p->headers_size>p->image_size || p->headers_size<p->section_table+(uint32_t)p->section_count*40){
        return fail(error,cap,"invalid/oversized image or header size");
    }
    image->bytes=(uint8_t *)calloc(p->image_size,1);
    image->valid=(uint8_t *)calloc(p->image_size,1);
    if(!image->bytes || !image->valid){ fail(error,cap,"out of memory"); goto bad; }
    image->size=p->image_size;
    memcpy(image->bytes,p->data,p->headers_size); memset(image->valid,1,p->headers_size);
    for(i=0;i<p->section_count;++i){
        const ps_section *s=&p->sections[i];
        uint64_t n=span(s);
        unsigned j;
        if(!ps_range(s->raw,s->raw_size,p->size) || !ps_range(s->va,n,image->size) ||
           overlap(s->va,n,0,p->headers_size)){ fail(error,cap,"invalid section mapping"); goto bad; }
        for(j=0;j<i;++j){
            if(overlap(s->va,n,p->sections[j].va,span(&p->sections[j]))){
                fail(error,cap,"ambiguous section mapping"); goto bad;
            }
        }
        if(s->raw_size){ memcpy(image->bytes+s->va,p->data+s->raw,s->raw_size); }
        memset(image->valid+s->va,1,(size_t)n);
    }
    if(delta){
        if(!d->address || d->size<8){ fail(error,cap,"rebased image has no usable relocation directory"); goto bad; }
        while(pos<d->size){
            size_t off,j;
            uint32_t page,block;
            if(!ps_range(d->address,(uint64_t)pos+8,UINT64_C(0x100000000)) ||
               !ps_range(pos,8,d->size) || ps_pe_map(p,d->address+pos,8,&off)!=PS_MAP_OK){
                fail(error,cap,"unreadable relocation block"); goto bad;
            }
            page=ps_u32(p->data+off); block=ps_u32(p->data+off+4);
            if(block<8 || block%2 || !ps_range(pos,block,d->size) ||
               ps_pe_map(p,d->address+pos,block,&off)!=PS_MAP_OK){
                fail(error,cap,"invalid relocation block"); goto bad;
            }
            for(j=8;j<block;j+=2){
                unsigned value=ps_u16(p->data+off+j),type=value>>12;
                uint64_t at=(uint64_t)page+(value&4095u);
                size_t width;
                if(++visited>PS_ITEM_LIMIT){ fail(error,cap,"relocation item limit reached"); goto bad; }
                if(!type){ continue; }
                if((type==10 && p->bits==64) || (type==3 && p->bits==32)){ width=type==10 ? 8u : 4u; }
                else{ fail(error,cap,"unsupported relocation type; comparison withheld"); goto bad; }
                if(!ps_range(at,width,image->size)){ fail(error,cap,"relocation exceeds image"); goto bad; }
                for(size_t k=0;k<width;++k){
                    if(image->valid[(size_t)at+k]!=1){ fail(error,cap,"relocation targets unavailable bytes"); goto bad; }
                }
                memset(image->valid+(size_t)at,5,width);
                if(width==8){ ps_w64(image->bytes+(size_t)at,ps_u64(image->bytes+(size_t)at)+delta); }
                else{ ps_w32(image->bytes+(size_t)at,ps_u32(image->bytes+(size_t)at)+(uint32_t)delta); }
                if(++image->relocations>PS_ITEM_LIMIT){ fail(error,cap,"relocation limit reached"); goto bad; }
            }
            pos+=block;
        }
    }
    for(size_t k=0;k<image->size;++k){ if(image->valid[k]==5){ image->valid[k]=3; } }
    mask.image=image; mask.width=(size_t)p->bits/8;
    if(!ps_pe_imports(p,mask_import,&mask,error,cap)){ goto bad; }
    return 1;
bad:
    ps_image_free(image); return 0;
}
/* Accept only the full ImageBase field equaling the observed module base.
   Other header bytes and unexpected ImageBase values remain comparable. */
int ps_pe_runtime_base(const ps_pe *p,uint64_t actual,size_t rva,const uint8_t *observed,
                       uint8_t *expected,size_t length){
    uint64_t field=(uint64_t)p->optional+24;
    size_t offset;
    if(p->bits!=64 || p->machine!=0x8664 || actual==p->base || field<rva ||
       !ps_range(field,8,p->headers_size) || !ps_range(field-rva,8,length)){ return 0; }
    offset=(size_t)(field-rva);
    if(ps_u64(expected+offset)!=p->base || ps_u64(observed+offset)!=actual){ return 0; }
    ps_w64(expected+offset,actual);return 1;
}
static int row_compare(const void *a,const void *b){
    const ps_row *x=(const ps_row *)a,*y=(const ps_row *)b;
    int order=strcmp(x->kind,y->kind);
    if(!order){ order=strcmp(x->name,y->name); }
    if(!order){ order=(x->address>y->address)-(x->address<y->address); }
    if(!order){ order=(x->size>y->size)-(x->size<y->size); }
    return order ? order : strcmp(x->detail,y->detail);
}
void ps_pe_diff(const ps_pe *a,const ps_pe *b,ps_report *r){
    ps_report x,y;
    size_t i=0,j=0;
    char before[65],after[65];
    ps_sha256(a->data,a->size,before);ps_sha256(b->data,b->size,after);
    if(strcmp(before,after)){
        ps_emit(r,"diff",PS_CHANGE,"file-content",0,b->size,"SHA256 %s -> %s",before,after);
    }
    ps_report_init(&x,"before");ps_report_init(&y,"after");
    ps_pe_report(a,&x);ps_pe_report(b,&y);
    qsort(x.rows,x.count,sizeof(*x.rows),row_compare);qsort(y.rows,y.count,sizeof(*y.rows),row_compare);
    while((i<x.count || j<y.count) && !r->limited){
        const ps_row *old=i<x.count ? &x.rows[i] : NULL,*now=j<y.count ? &y.rows[j] : NULL;
        int order;
        if(old && !strcmp(old->kind,"identity")){ ++i;continue; }
        if(now && !strcmp(now->kind,"identity")){ ++j;continue; }
        order=!old ? 1 : !now ? -1 : strcmp(old->kind,now->kind);
        if(!order){ order=strcmp(old->name,now->name); }
        if(order<0){
            ps_emit(r,"diff",PS_CHANGE,old->name,old->address,old->size,"removed %s | %s",old->kind,old->detail);++i;
        }else if(order>0){
            ps_emit(r,"diff",PS_CHANGE,now->name,now->address,now->size,"added %s | %s",now->kind,now->detail);++j;
        }else{
            if(row_compare(old,now)){
                ps_emit(r,"diff",PS_CHANGE,now->name,now->address,now->size,
                        "%s | BEFORE addr=0x%" PRIx64 " size=%" PRIu64 " %s | AFTER addr=0x%" PRIx64 " size=%" PRIu64 " %s",
                        old->kind,old->address,old->size,old->detail,now->address,now->size,now->detail);
            }
            ++i;++j;
        }
    }
    if(x.failed || y.failed || x.limited || y.limited || x.levels[PS_SKIP] || y.levels[PS_SKIP] ||
       x.levels[PS_ERROR] || y.levels[PS_ERROR]){
        ps_emit(r,"diff",PS_SKIP,"partial",0,0,"at least one input could not be fully analyzed");
    }
    ps_report_free(&x);ps_report_free(&y);
}
