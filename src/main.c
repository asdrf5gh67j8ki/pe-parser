#include "ps.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

static void help(void){
    puts("pe analyzer " PS_VERSION " - PE and process-memory inspection\n\n"
         "  pe-analyzer inspect FILE [options]\n"
         "  pe-analyzer diff BEFORE AFTER [options]\n"
         "  pe-analyzer scan PID [--module NAME] [--reference FILE] [--dump DIR] [options]\n"
         "  pe-analyzer scan --all [--module NAME] [options]\n\n"
         "  --html FILE   Standalone interactive report\n"
         "  --json FILE   JSON report; use - for JSON-only stdout\n"
         "  --summary     Compact terminal output; reports keep all rows\n"
         "  --no-color    Disable terminal colors (also respects NO_COLOR)\n"
         "  --version     Print version\n\n"
         "Live scans require Windows x64 and read access to the target.\n"
         "--reference requires --module and exactly one selected module.\n"
         "--dump writes bounded raw memory captures with a validity map.\n"
         "Exit: 0 completed, 1 incomplete/failure, 2 arguments, 3 findings.\n"
         "A change or review finding is not a malware verdict.");
}
static int run(int argc,char **argv){
    const char *json=NULL,*html=NULL,*command,*first=NULL,*second=NULL;
    int summary=0,no_color=0,i,result=0;
    ps_scan_options scan={0};
    ps_report report;
    if(argc<2){ help();return 2; }
    if(argc==2 && !strcmp(argv[1],"--help")){ help();return 0; }
    if(argc==2 && !strcmp(argv[1],"--version")){ puts(PS_VERSION);return 0; }
    command=argv[1];
    if(strcmp(command,"inspect") && strcmp(command,"diff") && strcmp(command,"scan")){ goto bad; }
    for(i=2;i<argc;++i){
        const char *a=argv[i];
        if(!strcmp(a,"--summary")){ summary=1; }
        else if(!strcmp(a,"--no-color")){ no_color=1; }
        else if(!strcmp(a,"--all")){ if(strcmp(command,"scan") || scan.all){ goto bad; }scan.all=1; }
        else if(!strcmp(a,"--json") || !strcmp(a,"--html") || !strcmp(a,"--module") ||
                !strcmp(a,"--reference") || !strcmp(a,"--dump")){
            const char **slot=!strcmp(a,"--json") ? &json : !strcmp(a,"--html") ? &html :
                !strcmp(a,"--module") ? &scan.module : !strcmp(a,"--reference") ? &scan.reference : &scan.dump;
            if(*slot || ++i>=argc || !*argv[i]){ goto bad; }
            *slot=argv[i];
        }else if(a[0]=='-' && a[1]=='-'){ goto bad; }
        else if(!first){ first=a; }
        else if(!second){ second=a; }
        else{ goto bad; }
    }
    if(!strcmp(command,"scan")){
        char *end;
        unsigned long pid;
        if(second || (scan.all && first) || (!scan.all && !first) ||
           (scan.reference && (!scan.module || scan.all)) || (scan.all && scan.dump)){ goto bad; }
        if(first){
            if(*first<'0' || *first>'9'){ goto bad; }
            errno=0;pid=strtoul(first,&end,10);
            if(errno || *end || !pid || pid>UINT32_MAX){ goto bad; }
            scan.pid=(uint32_t)pid;
        }
    }else if(scan.module || scan.reference || scan.dump || scan.all || !first ||
             (!strcmp(command,"diff") ? !second : second!=NULL)){ goto bad; }
    if((json && html && !strcmp(json,html)) ||
       (json && first && !strcmp(json,first)) || (html && first && !strcmp(html,first)) ||
       (json && second && !strcmp(json,second)) || (html && second && !strcmp(html,second)) ||
       (scan.reference && ((json && !strcmp(json,scan.reference)) || (html && !strcmp(html,scan.reference))))){ goto bad; }
    ps_report_init(&report,!strcmp(command,"scan") ? (scan.all ? "all accessible processes" : first) : first);
    if(!strcmp(command,"scan")){ if(!ps_scan(&report,&scan)){ result=1; } }
    else{
        size_t n=0,m=0;
        char error[256];
        uint8_t *a=ps_read_file(first,&n,error,sizeof(error)),*b=NULL;
        ps_pe pa,pb;
        if(!a || !ps_pe_parse(&pa,a,n,error,sizeof(error))){
            ps_emit(&report,"input",PS_ERROR,first,0,n,"%s",error);result=1;
        }else if(second){
            b=ps_read_file(second,&m,error,sizeof(error));
            if(!b || !ps_pe_parse(&pb,b,m,error,sizeof(error))){
                ps_emit(&report,"input",PS_ERROR,second,0,m,"%s",error);result=1;
            }else{ ps_pe_diff(&pa,&pb,&report); }
        }else{ ps_pe_report(&pa,&report); }
        free(a);free(b);
    }
    if(report.failed || report.limited || report.levels[PS_ERROR] || report.levels[PS_SKIP]){ result=1; }
    else if(report.levels[PS_CHANGE] || report.levels[PS_WARN]){ result=3; }
    if(!ps_output(&report,json,html,summary,no_color)){ result=1; }
    ps_report_free(&report);
    return result;
bad:
    fputs("Invalid arguments. Run pe-analyzer --help.\n",stderr);return 2;
}
#ifdef _WIN32
int wmain(int argc,wchar_t **wide){
    char **args=(char **)calloc((size_t)argc+1,sizeof(*args));
    int i,result=1;
    if(!args){ return 1; }
    for(i=0;i<argc;++i){
        int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide[i],-1,NULL,0,NULL,NULL);
        if(!n || !(args[i]=(char *)malloc((size_t)n)) ||
           !WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide[i],-1,args[i],n,NULL,NULL)){ goto done; }
    }
    result=run(argc,args);
done:
    for(i=0;i<argc;++i){ free(args[i]); }
    free(args);return result;
}
#else
int main(int argc,char **argv){ return run(argc,argv); }
#endif
