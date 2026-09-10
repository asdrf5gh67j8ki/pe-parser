#include "ps.h"
#ifndef _WIN32
int ps_scan(ps_report *r,const ps_scan_options *options){
    (void)options;
    ps_emit(r,"scan",PS_ERROR,"platform",0,0,"live scanning requires a native Windows x64 build");
    return 0;
}
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define MODULE_LIMIT 8192u
#define DUMP_LIMIT (128u*1024u*1024u)
#define DUMP_REGION_LIMIT (16u*1024u*1024u)
typedef struct { uint64_t base; uint32_t size; char *path; } module;
typedef struct {
    HANDLE process;
    DWORD pid;
    module *modules;
    size_t count;
    ps_report *report;
    const ps_scan_options *options;
    uint64_t dumped,compared,changed,unreadable,excluded;
} scan_context;
static const char *basename_of(const char *path){
    const char *p=path,*name=path;
    while(*p){ if(*p=='\\' || *p=='/'){ name=p+1; }++p; }
    return name;
}
static char *utf8(const wchar_t *wide){
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide,-1,NULL,0,NULL,NULL);
    char *s;
    if(!n){ return NULL; }
    s=(char *)malloc((size_t)n);
    if(s && !WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide,-1,s,n,NULL,NULL)){ free(s);s=NULL; }
    return s;
}
static wchar_t *wide_string(const char *s){
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,NULL,0);
    wchar_t *wide;
    if(!n){ return NULL; }
    wide=(wchar_t *)malloc((size_t)n*sizeof(*wide));
    if(wide && !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,wide,n)){ free(wide);wide=NULL; }
    return wide;
}
static int executable(DWORD p){
    p&=0xff;
    return p==PAGE_EXECUTE || p==PAGE_EXECUTE_READ || p==PAGE_EXECUTE_READWRITE || p==PAGE_EXECUTE_WRITECOPY;
}
static const char *protection(DWORD p){
    if(p&PAGE_GUARD){ return "GUARD"; }
    switch(p&0xff){
        case PAGE_NOACCESS:return "---";
        case PAGE_READONLY:return "R--";
        case PAGE_READWRITE:return "RW-";
        case PAGE_WRITECOPY:return "RC-";
        case PAGE_EXECUTE:return "--X";
        case PAGE_EXECUTE_READ:return "R-X";
        case PAGE_EXECUTE_READWRITE:return "RWX";
        case PAGE_EXECUTE_WRITECOPY:return "RCX";
        default:return "???";
    }
}
static const char *memory_type(DWORD t){
    return t==MEM_IMAGE ? "image" : t==MEM_PRIVATE ? "private" : t==MEM_MAPPED ? "mapped" : "unknown";
}
static const module *owner(const scan_context *c,uint64_t address){
    size_t i;
    for(i=0;i<c->count;++i){
        const module *m=&c->modules[i];
        if(address>=m->base && address-m->base<m->size){ return m; }
    }
    return NULL;
}
static const module *allocation_owner(const scan_context *c,uint64_t allocation){
    size_t i;
    for(i=0;i<c->count;++i){
        if(c->modules[i].base==allocation){ return &c->modules[i]; }
    }
    return NULL;
}
static SIZE_T safe_read(scan_context *c,uint64_t address,void *buffer,SIZE_T count){
    MEMORY_BASIC_INFORMATION region;
    SIZE_T received=0;
    if(!VirtualQueryEx(c->process,(LPCVOID)(uintptr_t)address,&region,sizeof(region)) ||
       region.State!=MEM_COMMIT || (region.Protect&(PAGE_GUARD|PAGE_NOACCESS)) ||
       !ps_range(address-(uint64_t)(uintptr_t)region.BaseAddress,count,region.RegionSize)){ return 0; }
    (void)ReadProcessMemory(c->process,(LPCVOID)(uintptr_t)address,buffer,count,&received);
    return received<=count ? received : 0;
}
static int write_handle(HANDLE h,const void *buffer,DWORD count){
    DWORD written=0;
    return WriteFile(h,buffer,count,&written,NULL) && written==count;
}
static void dump_region(scan_context *c,uint64_t address,uint64_t requested){
    wchar_t *directory;
    wchar_t raw_path[32768],map_path[32768];
    HANDLE raw=INVALID_HANDLE_VALUE,map=INVALID_HANDLE_VALUE;
    uint64_t length=requested,offset=0,received_total=0;
    char text[512];
    int ok=1,n;
    if(!c->options->dump){ return; }
    if(length>DUMP_REGION_LIMIT){ length=DUMP_REGION_LIMIT; }
    if(length>DUMP_LIMIT-c->dumped){ length=DUMP_LIMIT-c->dumped; }
    if(!length){
        ps_emit(c->report,"dumps",PS_SKIP,"budget",address,requested,"128 MiB dump budget exhausted");return;
    }
    directory=wide_string(c->options->dump);
    if(!directory){ goto failed; }
    if(!CreateDirectoryW(directory,NULL) && GetLastError()!=ERROR_ALREADY_EXISTS){ free(directory);goto failed; }
    if(wcslen(directory)>32000){ free(directory);goto failed; }
    _snwprintf(raw_path,32768,L"%ls\\%lu_%016llx.bin",directory,(unsigned long)c->pid,(unsigned long long)address);
    _snwprintf(map_path,32768,L"%ls\\%lu_%016llx.map.json",directory,(unsigned long)c->pid,(unsigned long long)address);
    free(directory);
    raw=CreateFileW(raw_path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(raw==INVALID_HANDLE_VALUE){ goto failed; }
    map=CreateFileW(map_path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(map==INVALID_HANDLE_VALUE){ CloseHandle(raw);DeleteFileW(raw_path);goto failed; }
    n=snprintf(text,sizeof(text),"{\"pid\":%lu,\"base\":\"0x%016" PRIx64 "\",\"requested\":%" PRIu64
               ",\"stored\":%" PRIu64 ",\"zero_bytes_in_unread_ranges_are_placeholders\":true,\"chunks\":[",
               (unsigned long)c->pid,address,requested,length);
    ok=write_handle(map,text,(DWORD)n);
    while(offset<length && ok){
        uint8_t bytes[4096]={0};
        SIZE_T take=(SIZE_T)(length-offset),got;
        SIZE_T boundary=4096u-(SIZE_T)((address+offset)&4095);
        if(take>boundary){ take=boundary; }
        got=safe_read(c,address+offset,bytes,take);
        if(got<take){ memset(bytes+got,0,take-got); }
        ok=write_handle(raw,bytes,(DWORD)take);
        n=snprintf(text,sizeof(text),"%s{\"offset\":%" PRIu64 ",\"requested\":%zu,\"read\":%zu}",
                   offset ? "," : "",offset,(size_t)take,(size_t)got);
        ok=ok && write_handle(map,text,(DWORD)n);received_total+=got;offset+=take;
    }
    if(ok){ ok=write_handle(map,"]}\n",3); }
    CloseHandle(raw);CloseHandle(map);
    if(!ok){ DeleteFileW(raw_path);DeleteFileW(map_path);goto failed; }
    c->dumped+=length;
    ps_emit(c->report,"dumps",length<requested || received_total<length ? PS_SKIP : PS_INFO,
            "raw-capture",address,length,"pid=%lu | %s/%lu_%016" PRIx64
            ".bin | read=%" PRIu64 " requested=%" PRIu64 " | validity map accompanies raw data",
            (unsigned long)c->pid,c->options->dump,(unsigned long)c->pid,address,received_total,requested);
    return;
failed:
    ps_emit(c->report,"dumps",PS_SKIP,"write-failed",address,requested,"could not create new dump files; existing files are never overwritten");
}
static int modules(scan_context *c){
    HMODULE *handles=NULL;
    DWORD needed=0,capacity=256,attempt;
    size_t i;
    for(attempt=0;attempt<5;++attempt){
        HMODULE *grown=(HMODULE *)realloc(handles,(size_t)capacity*sizeof(*handles));
        if(!grown){ free(handles);return 0; }handles=grown;
        if(!EnumProcessModulesEx(c->process,handles,capacity*(DWORD)sizeof(*handles),&needed,LIST_MODULES_ALL)){
            free(handles);return 0;
        }
        if(needed<=capacity*sizeof(*handles)){ break; }
        capacity=needed/(DWORD)sizeof(*handles)+64;
        if(capacity>MODULE_LIMIT){ free(handles);return 0; }
    }
    if(needed>capacity*sizeof(*handles)){ free(handles);return 0; }
    c->modules=(module *)calloc(needed/sizeof(*handles)+1,sizeof(*c->modules));
    if(!c->modules){ free(handles);return 0; }
    for(i=0;i<needed/sizeof(*handles);++i){
        MODULEINFO info;
        wchar_t path[32768];
        DWORD length;
        module *m;
        if(!GetModuleInformation(c->process,handles[i],&info,sizeof(info))){
            ps_emit(c->report,"modules",PS_SKIP,"unavailable",(uint64_t)(uintptr_t)handles[i],0,
                    "pid=%lu | module list changed or header was unreadable",(unsigned long)c->pid);continue;
        }
        length=GetModuleFileNameExW(c->process,handles[i],path,32768);
        if(!length || length>=32768){
            ps_emit(c->report,"modules",PS_SKIP,"path-unavailable",(uint64_t)(uintptr_t)info.lpBaseOfDll,info.SizeOfImage,
                    "pid=%lu | module path unavailable",(unsigned long)c->pid);
            path[0]=L'?';path[1]=0;
        }
        m=&c->modules[c->count];
        m->base=(uint64_t)(uintptr_t)info.lpBaseOfDll;m->size=info.SizeOfImage;m->path=utf8(path);
        if(!m->path){ free(handles);return 0; }
        ++c->count;
        ps_emit(c->report,"modules",PS_INFO,basename_of(m->path),m->base,m->size,
                "pid=%lu | %s",(unsigned long)c->pid,m->path);
    }
    free(handles);return 1;
}
static void regions(scan_context *c){
    SYSTEM_INFO sys;
    uint64_t address=0,last_unlisted=UINT64_MAX;
    unsigned count=0;
    GetNativeSystemInfo(&sys);
    while(address<(uint64_t)(uintptr_t)sys.lpMaximumApplicationAddress && !c->report->limited){
        MEMORY_BASIC_INFORMATION region;
        uint64_t base,next,allocation;
        const module *m;
        if(++count>262144){
            ps_emit(c->report,"regions",PS_SKIP,"limit",address,0,"region enumeration limit reached");break;
        }
        if(!VirtualQueryEx(c->process,(LPCVOID)(uintptr_t)address,&region,sizeof(region))){
            if(GetLastError()!=ERROR_INVALID_PARAMETER){
                ps_emit(c->report,"regions",PS_SKIP,"query-failed",address,0,"pid=%lu | Win32=%lu",
                        (unsigned long)c->pid,(unsigned long)GetLastError());
            }
            break;
        }
        base=(uint64_t)(uintptr_t)region.BaseAddress;
        if(region.RegionSize>UINT64_MAX-base || !(next=base+region.RegionSize) || next<=address){ break; }
        address=next;
        if(region.State!=MEM_COMMIT){ continue; }
        allocation=(uint64_t)(uintptr_t)region.AllocationBase;
        m=region.Type==MEM_IMAGE ? allocation_owner(c,allocation) : owner(c,base);
        ps_emit(c->report,"regions",(region.Protect&(PAGE_GUARD|PAGE_NOACCESS)) ? PS_SKIP : PS_INFO,
                m ? basename_of(m->path) : "unlisted",base,region.RegionSize,
                "pid=%lu | %s %s | allocation=0x%016" PRIx64 " | protection=0x%lx%s",
                (unsigned long)c->pid,memory_type(region.Type),protection(region.Protect),allocation,(unsigned long)region.Protect,
                (region.Protect&(PAGE_GUARD|PAGE_NOACCESS)) ? " | contents not read: guarded/inaccessible region" : "");
        if(region.Type==MEM_IMAGE && m &&
           (base<m->base || !ps_range(base-m->base,region.RegionSize,m->size))){
            ps_emit(c->report,"findings",PS_INFO,"image.extended",base,region.RegionSize,
                    "pid=%lu | allocation base matches %s | region extends beyond enumerated SizeOfImage=0x%" PRIx32
                    " | contents outside that range were not compared",
                    (unsigned long)c->pid,basename_of(m->path),m->size);
        }
        if(region.Type==MEM_IMAGE && !m && allocation!=last_unlisted){
            ps_emit(c->report,"findings",PS_WARN,"image.unlisted",allocation,region.RegionSize,
                    "pid=%lu | image mapping absent from the enumerated module list",(unsigned long)c->pid);
            last_unlisted=allocation;
        }
        if(executable(region.Protect) && !(region.Protect&PAGE_GUARD)){
            uint8_t probe[4096];
            SIZE_T got;
            if(region.Type!=MEM_IMAGE){
                ps_emit(c->report,"findings",PS_WARN,"executable.non-image",base,region.RegionSize,
                        "pid=%lu | %s %s | includes legitimate JIT/instrumentation allocations",
                        (unsigned long)c->pid,memory_type(region.Type),protection(region.Protect));
                got=safe_read(c,allocation,probe,sizeof(probe));
                if(got>=64 && probe[0]=='M' && probe[1]=='Z'){
                    uint32_t nt=ps_u32(probe+60);
                    if(ps_range(nt,24,got) && !memcmp(probe+nt,"PE\0\0",4)){
                        ps_emit(c->report,"findings",PS_WARN,"pe-like.non-image",allocation,got,
                                "pid=%lu | PE signature in non-image allocation; header candidate only",(unsigned long)c->pid);
                    }
                }
                dump_region(c,base,region.RegionSize);
            }
        }
    }
}
static void jump_pattern(scan_context *c,uint64_t address,const uint8_t *bytes,size_t n){
    uint64_t target=0,pointer=0;
    const char *form=NULL;
    MEMORY_BASIC_INFORMATION region;
    const module *m;
    if(n>=5 && bytes[0]==0xe9){ target=address+5+(uint64_t)(int64_t)(int32_t)ps_u32(bytes+1);form="jmp rel32"; }
    else if(n>=2 && bytes[0]==0xeb){ target=address+2+(uint64_t)(int64_t)(int8_t)bytes[1];form="jmp rel8"; }
    else if(n>=6 && bytes[0]==0xff && bytes[1]==0x25){
        uint8_t dest[8];
        pointer=address+6+(uint64_t)(int64_t)(int32_t)ps_u32(bytes+2);
        if(safe_read(c,pointer,dest,8)==8){ target=ps_u64(dest);form="jmp [rip+disp32]"; }
    }else if(n>=12 && bytes[0]==0x48 && bytes[1]==0xb8 && bytes[10]==0xff && bytes[11]==0xe0){
        target=ps_u64(bytes+2);form="mov rax,imm64; jmp rax";
    }
    if(!form){ return; }
    m=owner(c,target);memset(&region,0,sizeof(region));
    (void)VirtualQueryEx(c->process,(LPCVOID)(uintptr_t)target,&region,sizeof(region));
    ps_emit(c->report,"hooks",PS_WARN,form,address,n,
            "pid=%lu | possible transfer at changed bytes | target=0x%016" PRIx64 " | owner=%s | %s %s | pattern, not disassembly proof",
            (unsigned long)c->pid,target,m ? basename_of(m->path) : "unlisted",memory_type(region.Type),protection(region.Protect));
}
static void compare_range(scan_context *c,const module *m,const ps_pe *p,const ps_image *image,
                          uint32_t rva,uint32_t length,const char *name){
    uint64_t done=0,checked=0,changed=0,missing=0,excluded=0;
    if(!ps_range(rva,length,image->size) || !ps_range(m->base,(uint64_t)rva+length,UINT64_MAX)){
        ps_emit(c->report,"comparison",PS_SKIP,name,m->base+rva,length,"invalid reference range");return;
    }
    while(done<length && !c->report->limited){
        uint8_t a[4096],b[4096];
        uint64_t address=m->base+rva+done;
        SIZE_T take=(SIZE_T)(length-done),got,again;
        size_t i=0,off=(size_t)rva+(size_t)done;
        int page_changed=0;
        SIZE_T boundary=4096u-(SIZE_T)(address&4095);
        if(take>boundary){ take=boundary; }
        got=safe_read(c,address,a,take);again=got ? safe_read(c,address,b,got) : 0;
        if(again!=got || (got && memcmp(a,b,got))){
            ps_emit(c->report,"comparison",PS_SKIP,"unstable-read",address,take,"pid=%lu | %s changed between reads",(unsigned long)c->pid,name);
            missing+=take;done+=take;continue;
        }
        if(got<take){
            ps_emit(c->report,"comparison",PS_SKIP,"unreadable",address+got,take-got,
                    "pid=%lu | module=%s | section=%s",(unsigned long)c->pid,basename_of(m->path),name);
            missing+=take-got;
        }
        /* Both reads agreed. Reuse the second buffer for expected bytes. */
        memcpy(b,image->bytes+off,got);
        if(ps_pe_runtime_base(p,m->base,off,a,b,got)){
            ps_emit(c->report,"headers",PS_INFO,"ImageBase.runtime",m->base+p->optional+24,8,
                    "pid=%lu | module=%s | RVA=0x%" PRIx64 " | preferred=0x%016" PRIx64
                    " | observed=0x%016" PRIx64 " | equals enumerated module base; normalized for comparison",
                    (unsigned long)c->pid,basename_of(m->path),(uint64_t)p->optional+24,p->base,m->base);
        }
        for(size_t k=0;k<got;){
            size_t start=k,file_offset=0;
            if(image->valid[off+k]!=3){ ++k;continue; }
            while(k<got && image->valid[off+k]==3){ ++k; }
            if(!memcmp(a+start,image->bytes+off+start,k-start) &&
               ps_pe_map(p,(uint32_t)(off+start),k-start,&file_offset)==PS_MAP_OK &&
               memcmp(a+start,p->data+file_offset,k-start)){
                char original[65],observed[65];
                ps_hex(p->data+file_offset,k-start,original,sizeof(original));
                ps_hex(a+start,k-start,observed,sizeof(observed));
                ps_emit(c->report,"relocations",PS_INFO,"normalized-match",address+start,k-start,
                        "pid=%lu | module=%s | section=%s | RVA=0x%zx | file=0x%zx | original=%s | observed=%s | matches supported relocation normalization",
                        (unsigned long)c->pid,basename_of(m->path),name,off+start,file_offset,original,observed);
            }
        }
        while(i<got && !c->report->limited){
            size_t start,bytes,file_offset=0;
            char expected[65],observed[65];
            ps_mapping mapping;
            if(image->valid[off+i]!=1 && image->valid[off+i]!=3){ ++excluded;++i;continue; }
            ++checked;
            if(a[i]==b[i]){ ++i;continue; }
            start=i++;
            while(i<got && (image->valid[off+i]==1 || image->valid[off+i]==3) && a[i]!=b[i]){
                ++i;++checked;
            }
            bytes=i-start;changed+=bytes;page_changed=1;
            ps_hex(b+start,bytes,expected,sizeof(expected));ps_hex(a+start,bytes,observed,sizeof(observed));
            mapping=ps_pe_map(p,(uint32_t)(off+start),bytes,&file_offset);
            ps_emit(c->report,"patches",PS_CHANGE,name,address+start,bytes,
                    "pid=%lu | module=%s | RVA=0x%08" PRIx32 " | file=0x%zx (%s) | expected=%s | observed=%s%s",
                    (unsigned long)c->pid,basename_of(m->path),(uint32_t)(off+start),file_offset,ps_mapping_name(mapping),
                    expected,observed,bytes>32 ? " | byte preview limited to 32; range size is complete" : "");
            jump_pattern(c,address+start,a+start,got-start>16 ? 16u : got-start);
        }
        if(page_changed){ dump_region(c,address,take); }
        done+=take;
    }
    c->compared+=checked;c->changed+=changed;c->unreadable+=missing;c->excluded+=excluded;
    ps_emit(c->report,"comparison",PS_INFO,name,m->base+rva,length,
            "pid=%lu | %s | compared=%" PRIu64 " changed=%" PRIu64 " unreadable=%" PRIu64 " excluded=%" PRIu64,
            (unsigned long)c->pid,basename_of(m->path),checked,changed,missing,excluded);
}
typedef struct { scan_context *c; const module *m; } import_context;
static int inspect_import(void *context,const char *dll,const char *name,uint32_t slot,int delay){
    import_context *x=(import_context *)context;
    uint8_t raw[8],again[8];
    uint64_t target,address=x->m->base+slot;
    MEMORY_BASIC_INFORMATION region;
    const module *m;
    ps_level level=PS_INFO;
    if(safe_read(x->c,address,raw,8)!=8 || safe_read(x->c,address,again,8)!=8 || memcmp(raw,again,8)){
        ps_emit(x->c->report,"iat",PS_SKIP,name,address,8,"pid=%lu | unreadable/unstable import slot",(unsigned long)x->c->pid);
        return !x->c->report->limited;
    }
    target=ps_u64(raw);m=owner(x->c,target);memset(&region,0,sizeof(region));
    if(!VirtualQueryEx(x->c->process,(LPCVOID)(uintptr_t)target,&region,sizeof(region)) ||
       region.State!=MEM_COMMIT || (region.Protect&(PAGE_NOACCESS|PAGE_GUARD))){ level=PS_SKIP; }
    else if(region.Type!=MEM_IMAGE || !m){ level=PS_WARN; }
    ps_emit(x->c->report,"iat",level,name,address,8,
            "pid=%lu | source=%s | declared=%s | %s | target=0x%016" PRIx64 " | owner=%s | %s %s | destination inventory; forwarding not verified",
            (unsigned long)x->c->pid,basename_of(x->m->path),dll,delay ? "delay" : "normal",target,
            m ? basename_of(m->path) : "unlisted",memory_type(region.Type),protection(region.Protect));
    return !x->c->report->limited;
}
static void inspect_module(scan_context *c,const module *m){
    const char *path=c->options->reference ? c->options->reference : m->path;
    char error[256],hash[65];
    size_t size;
    uint8_t *file=ps_read_file(path,&size,error,sizeof(error));
    ps_pe pe;
    ps_image image;
    import_context imports={c,m};
    unsigned i;
    if(!file || !ps_pe_parse(&pe,file,size,error,sizeof(error))){
        ps_emit(c->report,"reference",PS_SKIP,basename_of(m->path),m->base,m->size,
                "pid=%lu | %s | %s",(unsigned long)c->pid,path,error);free(file);return;
    }
    if(pe.machine!=0x8664 || pe.bits!=64 || pe.image_size!=m->size){
        ps_emit(c->report,"reference",PS_SKIP,"image-mismatch",m->base,m->size,
                "pid=%lu | file image size=%" PRIu32 " loaded size=%" PRIu32 " machine=0x%04x",
                (unsigned long)c->pid,pe.image_size,m->size,pe.machine);free(file);return;
    }
    ps_sha256(file,size,hash);
    ps_emit(c->report,"reference",PS_INFO,basename_of(m->path),m->base,size,
            "pid=%lu | %s | SHA256=%s | %s",(unsigned long)c->pid,path,hash,
            c->options->reference ? "user-supplied reference" : "current file at module path; original loaded file is not attested");
    if(!ps_pe_image(&pe,m->base,&image,error,sizeof(error))){
        ps_emit(c->report,"comparison",PS_SKIP,basename_of(m->path),m->base,m->size,
                "pid=%lu | %s",(unsigned long)c->pid,error);free(file);return;
    }
    ps_emit(c->report,"relocations",PS_INFO,basename_of(m->path),m->base,0,
            "pid=%lu | preferred=0x%016" PRIx64 " | applied=%" PRIu64 " | import slot bytes excluded=%" PRIu64,
            (unsigned long)c->pid,pe.base,image.relocations,image.masked);
    compare_range(c,m,&pe,&image,0,pe.headers_size,"headers");
    for(i=0;i<pe.section_count && !c->report->limited;++i){
        const ps_section *s=&pe.sections[i];
        if(s->flags&0x20000000u){
            uint32_t n=s->virtual_size>s->raw_size ? s->virtual_size : s->raw_size;
            compare_range(c,m,&pe,&image,s->va,n,s->name);
        }
    }
    if(!ps_pe_imports(&pe,inspect_import,&imports,error,sizeof(error))){
        ps_emit(c->report,"iat",PS_SKIP,basename_of(m->path),m->base,0,"pid=%lu | %s",(unsigned long)c->pid,error);
    }
    ps_image_free(&image);free(file);
}
static int scan_one(ps_report *r,const ps_scan_options *options,DWORD pid){
    scan_context c;
    USHORT process_machine=0,native_machine=0;
    FILETIME created,exited,kernel,user;
    size_t i,selected=0;
    int result=1;
    typedef BOOL (WINAPI *wow64_fn)(HANDLE,USHORT *,USHORT *);
    wow64_fn architecture;
    FARPROC proc;
    memset(&c,0,sizeof(c));c.pid=pid;c.report=r;c.options=options;
    c.process=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
    if(!c.process){
        ps_emit(r,"process",PS_SKIP,"access-denied",pid,0,"OpenProcess Win32=%lu",(unsigned long)GetLastError());return 0;
    }
    proc=GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"IsWow64Process2");architecture=NULL;
    if(sizeof(architecture)==sizeof(proc)){ memcpy(&architecture,&proc,sizeof(proc)); }
    if(!architecture || !architecture(c.process,&process_machine,&native_machine) ||
       process_machine!=IMAGE_FILE_MACHINE_UNKNOWN || native_machine!=IMAGE_FILE_MACHINE_AMD64){
        ps_emit(r,"process",PS_SKIP,"architecture",pid,0,"live target must be native AMD64; WOW64/ARM64 are unsupported");
        result=0;goto done;
    }
    if(GetProcessTimes(c.process,&created,&exited,&kernel,&user)){
        uint64_t stamp=(uint64_t)created.dwLowDateTime|(uint64_t)created.dwHighDateTime<<32;
        ps_emit(r,"process",PS_INFO,"identity",pid,0,"pid=%lu | creation FILETIME=%" PRIu64 " | live read-only scan; not an atomic snapshot",
                (unsigned long)pid,stamp);
    }
    if(!modules(&c)){
        ps_emit(r,"modules",PS_SKIP,"enumeration",pid,0,"module enumeration failed or changed repeatedly");
        regions(&c);result=0;goto done;
    }
    for(i=0;i<c.count;++i){
        if(!options->module || !_stricmp(basename_of(c.modules[i].path),options->module)){ ++selected; }
    }
    if((options->reference && selected!=1) || (options->module && !selected)){
        ps_emit(r,"modules",PS_ERROR,"selection",pid,selected,"module filter must match; explicit reference requires exactly one match");
        result=0;goto done;
    }
    regions(&c);
    for(i=0;i<c.count && !r->limited;++i){
        if(!options->module || !_stricmp(basename_of(c.modules[i].path),options->module)){ inspect_module(&c,&c.modules[i]); }
    }
    ps_emit(r,"summary",PS_INFO,"scan",pid,c.compared,
            "modules=%zu selected=%zu | changed=%" PRIu64 " unreadable=%" PRIu64 " excluded=%" PRIu64 " dumped=%" PRIu64,
            c.count,selected,c.changed,c.unreadable,c.excluded,c.dumped);
done:
    for(i=0;i<c.count;++i){ free(c.modules[i].path); }
    free(c.modules);CloseHandle(c.process);return result;
}
int ps_scan(ps_report *r,const ps_scan_options *options){
    DWORD *pids,needed=0;
    size_t i;
    int success=1;
    if(sizeof(void *)!=8){
        ps_emit(r,"scan",PS_ERROR,"architecture",0,0,"scanner must be built for x64");return 0;
    }
    if(!options->all){ return scan_one(r,options,options->pid); }
    pids=(DWORD *)calloc(65536,sizeof(*pids));
    if(!pids){ return 0; }
    if(!EnumProcesses(pids,65536u*(DWORD)sizeof(*pids),&needed) || needed>=65536u*sizeof(*pids)){
        ps_emit(r,"process",PS_ERROR,"enumeration",0,0,"process enumeration failed or exceeded limit");free(pids);return 0;
    }
    for(i=0;i<needed/sizeof(*pids) && !r->limited;++i){
        if(pids[i] && pids[i]!=GetCurrentProcessId() && !scan_one(r,options,pids[i])){ success=0; }
    }
    free(pids);return success;
}
#endif
