#include "ps.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <inttypes.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif
#include "ui.h"

static char *duplicate(const char *s){
    size_t n=strlen(s)+1;
    char *copy=(char *)malloc(n);
    if(copy){ memcpy(copy,s,n); }
    return copy;
}
const char *ps_level_name(ps_level level){
    static const char *names[]={"info","change","review","error","unavailable"};
    return names[(unsigned)level<5 ? level : PS_ERROR];
}
void ps_report_init(ps_report *r,const char *subject){
    time_t now=time(NULL);
    struct tm *utc=gmtime(&now);
    memset(r,0,sizeof(*r));
    r->subject=duplicate(subject);
    if(!r->subject){ r->failed=1; }
    if(utc){ strftime(r->started,sizeof(r->started),"%Y-%m-%dT%H:%M:%SZ",utc); }
}
void ps_report_free(ps_report *r){
    size_t i;
    for(i=0;i<r->count;++i){ free(r->rows[i].kind);free(r->rows[i].name);free(r->rows[i].detail); }
    free(r->rows);free(r->subject);memset(r,0,sizeof(*r));
}
void ps_emit(ps_report *r,const char *kind,ps_level level,const char *name,uint64_t address,uint64_t size,const char *format,...){
    ps_row row;
    va_list args,copy;
    int length;
    size_t allocation;
    if(r->failed || r->limited){ return; }
    if(r->count>=PS_ROW_LIMIT){ r->limited=1; return; }
    va_start(args,format); va_copy(copy,args);
    length=vsnprintf(NULL,0,format,copy); va_end(copy);
    if(length<0 || length>32768){ va_end(args);r->limited=1;return; }
    allocation=(size_t)length+1+strlen(kind)+1+strlen(name)+1;
    if(allocation>64u*1024u*1024u-r->string_bytes){ va_end(args);r->limited=1;return; }
    row.detail=(char *)malloc((size_t)length+1);
    row.kind=duplicate(kind);row.name=duplicate(name);
    if(!row.detail || !row.kind || !row.name){
        free(row.detail);free(row.kind);free(row.name);va_end(args);r->failed=1;return;
    }
    vsnprintf(row.detail,(size_t)length+1,format,args);va_end(args);
    row.level=level;row.address=address;row.size=size;
    if(r->count==r->capacity){
        size_t cap=r->capacity ? r->capacity*2 : 256;
        ps_row *grown;
        if(cap>PS_ROW_LIMIT){ cap=PS_ROW_LIMIT; }
        grown=(ps_row *)realloc(r->rows,cap*sizeof(*grown));
        if(!grown){ free(row.detail);free(row.kind);free(row.name);r->failed=1;return; }
        r->rows=grown;r->capacity=cap;
    }
    r->rows[r->count++]=row;r->string_bytes+=allocation;++r->levels[level];
}
static void json_string(FILE *f,const char *s){
    const unsigned char *p=(const unsigned char *)(s ? s : "");
    fputc('"',f);
    while(*p){
        unsigned char c=*p;
        if(c=='"' || c=='\\'){ fputc('\\',f);fputc(c,f);++p; }
        else if(c<32 || c==127 || c=='<' || c=='>' || c=='&'){
            fprintf(f,"\\u%04x",(unsigned)c);++p;
        }else if(c<128){ fputc(c,f);++p; }
        else{
            unsigned n=c>=0xc2 && c<=0xdf ? 2u : c>=0xe0 && c<=0xef ? 3u : c>=0xf0 && c<=0xf4 ? 4u : 0u;
            unsigned i;
            int good=n!=0;
            for(i=1;i<n && good;++i){ if(!p[i] || (p[i]&0xc0)!=0x80){ good=0; } }
            if(good && ((c==0xe0 && p[1]<0xa0) || (c==0xed && p[1]>=0xa0) ||
                        (c==0xf0 && p[1]<0x90) || (c==0xf4 && p[1]>=0x90))){ good=0; }
            if(good){ fwrite(p,1,n,f);p+=n; }
            else{ fprintf(f,"\\u%04x",(unsigned)c);++p; }
        }
    }
    fputc('"',f);
}
static void json_report(FILE *f,const ps_report *r){
    size_t i;
    fprintf(f,"{\"schema\":1,\"version\":\"%s\",\"subject\":",PS_VERSION);json_string(f,r->subject);
    fputs(",\"started\":",f);json_string(f,r->started);
    fprintf(f,",\"limited\":%s,\"failed\":%s,\"counts\":[%u,%u,%u,%u,%u],\"rows\":[",
            r->limited ? "true" : "false",r->failed ? "true" : "false",
            r->levels[0],r->levels[1],r->levels[2],r->levels[3],r->levels[4]);
    for(i=0;i<r->count;++i){
        const ps_row *row=&r->rows[i];
        fprintf(f,"%s{\"id\":%zu,\"kind\":",i ? "," : "",i+1);json_string(f,row->kind);
        fputs(",\"status\":",f);json_string(f,ps_level_name(row->level));
        fputs(",\"name\":",f);json_string(f,row->name);
        fprintf(f,",\"address\":\"0x%016" PRIx64 "\",\"size\":%" PRIu64 ",\"detail\":",row->address,row->size);
        json_string(f,row->detail);fputc('}',f);
    }
    fputs("]}\n",f);
}
static void safe_text(FILE *f,const char *s){
    const unsigned char *p=(const unsigned char *)(s ? s : "");
    while(*p){
        if(*p<32 || *p==127 || *p>=128){ fprintf(f,"\\x%02x",(unsigned)*p); }
        else{ fputc(*p,f); }
        ++p;
    }
}
int ps_export(const ps_report *r,const char *json_path,const char *html_path){
    int ok=1;
    size_t i;
    if(json_path){
        FILE *f=!strcmp(json_path,"-") ? stdout : ps_fopen(json_path,"wbx");
        if(!f){ fprintf(stderr,"Cannot create JSON report.\n");ok=0; }
        else{
            json_report(f,r);
            if(ferror(f)){ ok=0; }
            if(f!=stdout && fclose(f)){ ok=0; }
        }
    }
    if(html_path){
        FILE *f=ps_fopen(html_path,"wbx");
        if(!f){ fprintf(stderr,"Cannot create HTML report.\n");ok=0; }
        else{
            for(i=0;ps_html_head[i];++i){ fputs(ps_html_head[i],f); }
            json_report(f,r);
            for(i=0;ps_html_tail[i];++i){ fputs(ps_html_tail[i],f); }
            if(ferror(f)){ ok=0; }
            if(fclose(f)){ ok=0; }
        }
    }
    return ok;
}
int ps_output(ps_report *r,const char *json_path,const char *html_path,int summary,int no_color){
    int color=0,ok=1;
    size_t i;
#ifdef _WIN32
    HANDLE console=GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD old_mode=0;
    if(!no_color && !getenv("NO_COLOR") && GetConsoleMode(console,&old_mode)){
        color=SetConsoleMode(console,old_mode|ENABLE_VIRTUAL_TERMINAL_PROCESSING)!=0;
    }
#else
    color=!no_color && !getenv("NO_COLOR") && isatty(STDOUT_FILENO);
#endif
    ok=ps_export(r,json_path,html_path);
    if(!json_path || strcmp(json_path,"-")){
        const char *accent=color ? "\033[97m" : "",*dim=color ? "\033[38;5;245m" : "",*reset=color ? "\033[0m" : "";
        printf("\n%spe analyzer%s  %s%s  /  %s%s\n",accent,reset,dim,PS_VERSION,r->started,reset);
        printf("  ");safe_text(stdout,r->subject);printf("\n\n");
        printf("  %zu records    %u changes    %u review    %u unavailable    %u errors\n\n",
               r->count,r->levels[PS_CHANGE],r->levels[PS_WARN],r->levels[PS_SKIP],r->levels[PS_ERROR]);
        for(i=0;i<r->count;++i){
            const ps_row *row=&r->rows[i];
            const char *tone=dim;
            if(summary && row->level==PS_INFO && strcmp(row->kind,"summary") && strcmp(row->kind,"identity")){ continue; }
            if(color && row->level==PS_WARN){ tone="\033[38;5;250m"; }
            if(color && row->level==PS_CHANGE){ tone="\033[38;5;255m"; }
            if(color && row->level==PS_ERROR){ tone="\033[1;97m"; }
            printf("%s  %-11s%s  %-13s  0x%016" PRIx64 "  %10" PRIu64 "  ",
                   tone,ps_level_name(row->level),reset,row->kind,row->address,row->size);
            safe_text(stdout,row->name);printf("\n%s      ",dim);safe_text(stdout,row->detail);printf("%s\n",reset);
        }
        if(r->limited || r->failed){ printf("\n  INCOMPLETE: output/memory limit reached.\n"); }
        if(html_path){ printf("\n  HTML  ");safe_text(stdout,html_path);printf("\n"); }
        if(json_path){ printf("  JSON  ");safe_text(stdout,json_path);printf("\n"); }
        printf("\n");
        if(ferror(stdout)){ ok=0; }
    }
#ifdef _WIN32
    if(color){ SetConsoleMode(console,old_mode); }
#endif
    return ok;
}
