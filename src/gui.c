/* Native Win32 report explorer. The engine is shared with the CLI. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <stdlib.h>
#include <wchar.h>
#include <errno.h>
#include <process.h>
#include "ps.h"

#ifdef _MSC_VER
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

enum { ID_MODE=100,ID_FIRST,ID_SECOND,ID_MODULE,ID_BROWSE1,ID_BROWSE2,
       ID_RUN,ID_SEARCH,ID_LEVEL,ID_EXPAND,ID_COLLAPSE,ID_JSON,ID_HTML,ID_COPY,
       ID_TREE,ID_TABLE,ID_DETAIL,ID_QUIT };
#define WM_RESULT (WM_APP+1)
#define BG RGB(27,27,27)
#define PANEL RGB(34,34,34)
#define LINE RGB(58,58,58)
#define FG RGB(223,223,223)
#define MUTED RGB(165,165,165)
#define SELECTED RGB(68,68,68)

typedef struct { wchar_t *name,*detail; wchar_t address[24],size[32],level[20]; size_t group; } display_row;
typedef struct { const char *kind; wchar_t *name; size_t count,matched; int collapsed; } group;
typedef struct { size_t row,group; } view_row;
typedef struct { ps_report report; int mode; char *first,*second,*module; HWND window; } job;
typedef struct {
    HWND window,mode,first,second,module,browse1,browse2,run,search,level,tree,table,detail,status;
    HWND json,html,copy,expand,collapse,labels[5],detail_label;
    HFONT font,mono,bold;
    HBRUSH background,panel;
    HIMAGELIST row_height;
    ps_report report;
    display_row *rows;
    group *groups;
    view_row *view;
    size_t group_count,view_count,matched;
    int category,sort_column,descending,closing,ready,smoke,exit_code;
    UINT dpi;
    int split,dragging;
    HANDLE thread;
    job *pending;
    const wchar_t *smoke_export;
} application;
static application app;

static int px(int value){ return MulDiv(value,(int)app.dpi,96); }
static wchar_t *wide(const char *s){
    int n=MultiByteToWideChar(CP_UTF8,0,s,-1,NULL,0);
    wchar_t *p=n>0 ? (wchar_t *)calloc((size_t)n,sizeof(*p)) : NULL;
    if(p){ MultiByteToWideChar(CP_UTF8,0,s,-1,p,n); }
    return p;
}
static char *utf8(const wchar_t *s){
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s,-1,NULL,0,NULL,NULL);
    char *p=n>0 ? (char *)malloc((size_t)n) : NULL;
    if(p){ WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s,-1,p,n,NULL,NULL); }
    return p;
}
static char *input(HWND control){
    int n=GetWindowTextLengthW(control);
    wchar_t *s=(wchar_t *)calloc((size_t)n+1,sizeof(*s));
    char *result;
    if(!s){ return NULL; }
    GetWindowTextW(control,s,n+1);result=utf8(s);free(s);return result;
}
static void message(const wchar_t *s){ SetWindowTextW(app.status,s); }
static void error(const wchar_t *s){ MessageBoxW(app.window,s,L"pe analyzer",MB_OK|MB_ICONERROR); }
static HWND control(const wchar_t *kind,const wchar_t *text,DWORD style,int id){
    HWND w=CreateWindowExW(0,kind,text,WS_CHILD|WS_VISIBLE|style,0,0,0,0,
                          app.window,(HMENU)(INT_PTR)id,GetModuleHandleW(NULL),NULL);
    if(w){ SendMessageW(w,WM_SETFONT,(WPARAM)app.font,TRUE);SetWindowTheme(w,L"",L""); }
    return w;
}
static HWND button(const wchar_t *s,int id){ return control(L"BUTTON",s,WS_TABSTOP|BS_OWNERDRAW,id); }
static void move(HWND w,int x,int y,int width,int height){ MoveWindow(w,px(x),px(y),px(width),px(height),TRUE); }
static void layout(void){
    RECT r;
    int width,height,tree=190,top=105,detail;
    GetClientRect(app.window,&r);width=MulDiv(r.right,96,(int)app.dpi);height=MulDiv(r.bottom,96,(int)app.dpi);
    detail=app.split;
    if(detail<100){ detail=100; }
    if(detail>height-top-120){ detail=height-top-120; }
    app.split=detail;
    move(app.mode,7,7,130,160);move(app.labels[0],146,12,52,18);
    move(app.first,198,7,width-398,24);move(app.browse1,width-195,7,30,24);move(app.run,width-158,7,150,24);
    move(app.labels[1],7,42,68,18);move(app.second,78,36,width-565,24);move(app.browse2,width-482,36,30,24);
    move(app.labels[2],width-443,42,49,18);move(app.module,width-390,36,185,24);
    move(app.json,width-198,36,91,24);move(app.html,width-101,36,93,24);
    move(app.labels[3],7,77,40,18);move(app.search,49,70,width-668,25);move(app.level,width-612,70,132,180);
    move(app.expand,width-472,70,92,25);move(app.collapse,width-374,70,96,25);move(app.copy,width-272,70,112,25);
    move(app.labels[4],width-154,76,147,18);
    move(app.tree,0,top,tree,height-top-24);
    move(app.table,tree+1,top,width-tree-1,height-top-detail-29);
    if(app.table){
        int remaining=px(width-tree-20)-ListView_GetColumnWidth(app.table,0)-ListView_GetColumnWidth(app.table,2)
            -ListView_GetColumnWidth(app.table,3)-ListView_GetColumnWidth(app.table,4);
        ListView_SetColumnWidth(app.table,1,remaining>px(180) ? remaining : px(180));
    }
    move(app.detail_label,tree+6,height-detail-20,width-tree-10,20);
    move(app.detail,tree+5,height-detail+2,width-tree-10,detail-30);
    move(app.status,6,height-22,width-12,20);
    InvalidateRect(app.window,NULL,FALSE);
}
static BOOL CALLBACK set_font(HWND w,LPARAM p){ SendMessageW(w,WM_SETFONT,(WPARAM)p,TRUE);return TRUE; }
static void fonts(void){
    HFONT old=app.font,old_mono=app.mono,old_bold=app.bold;
    app.font=CreateFontW(-px(12),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    app.mono=CreateFontW(-px(12),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Consolas");
    app.bold=CreateFontW(-px(12),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    if(app.window){ EnumChildWindows(app.window,set_font,(LPARAM)app.font); }
    if(app.detail){ SendMessageW(app.detail,WM_SETFONT,(WPARAM)app.mono,TRUE); }
    if(app.table){
        HIMAGELIST image=ImageList_Create(1,px(21),ILC_COLOR32,1,1);
        ListView_SetImageList(app.table,image,LVSIL_SMALL);
        if(app.row_height){ ImageList_Destroy(app.row_height); }
        app.row_height=image;
    }
    if(old){ DeleteObject(old); }if(old_mono){ DeleteObject(old_mono); }if(old_bold){ DeleteObject(old_bold); }
}
static void free_view(void){
    size_t i;
    for(i=0;app.rows && i<app.report.count;++i){ free(app.rows[i].name);free(app.rows[i].detail); }
    for(i=0;i<app.group_count;++i){ free(app.groups[i].name); }
    free(app.rows);free(app.groups);free(app.view);
    app.rows=NULL;app.groups=NULL;app.view=NULL;app.group_count=0;app.view_count=0;
}
static void free_job(job *j){
    if(j){ ps_report_free(&j->report);free(j->first);free(j->second);free(j->module);free(j); }
}
static void status(void){
    wchar_t s[512];
    swprintf(s,512,L"%ls | %zu / %zu records | Changes: %u | Review: %u | Unavailable: %u | Errors: %u%ls",
             app.thread ? L"Analysis running; previous result displayed" : L"Ready",app.matched,app.report.count,
             app.report.levels[PS_CHANGE],app.report.levels[PS_WARN],app.report.levels[PS_SKIP],app.report.levels[PS_ERROR],
             app.report.failed || app.report.limited ? L" | INCOMPLETE: allocation/output limit" : L"");
    message(s);
}
static int compare_view(const void *a,const void *b){
    const view_row *x=(const view_row *)a,*y=(const view_row *)b;
    const ps_row *rx,*ry;
    int order=0;
    if(x->group!=y->group){ return x->group<y->group ? -1 : 1; }
    if(x->row==SIZE_MAX || y->row==SIZE_MAX){ return x->row==y->row ? 0 : x->row==SIZE_MAX ? -1 : 1; }
    rx=&app.report.rows[x->row];ry=&app.report.rows[y->row];
    if(app.sort_column==0){ order=lstrcmpiW(app.rows[x->row].name,app.rows[y->row].name); }
    else if(app.sort_column==1){ order=lstrcmpiW(app.rows[x->row].detail,app.rows[y->row].detail); }
    else if(app.sort_column==2){ order=rx->address<ry->address ? -1 : rx->address>ry->address; }
    else if(app.sort_column==3){ order=rx->size<ry->size ? -1 : rx->size>ry->size; }
    else if(app.sort_column==4){ order=rx->level<ry->level ? -1 : rx->level>ry->level; }
    if(order){ return app.descending ? (order>0 ? -1 : 1) : (order>0 ? 1 : -1); }
    return x->row<y->row ? -1 : x->row>y->row;
}
static void filter(void){
    wchar_t query[1025];
    size_t i;
    int level=(int)SendMessageW(app.level,CB_GETCURSEL,0,0)-1;
    if(!app.ready){ return; }
    GetWindowTextW(app.search,query,1025);
    app.view_count=0;app.matched=0;
    for(i=0;i<app.group_count;++i){ app.groups[i].matched=0; }
    for(i=0;i<app.report.count;++i){
        display_row *row=&app.rows[i];group *g=&app.groups[row->group];
        if((app.category>=0 && row->group!=(size_t)app.category) ||
           (level>=0 && (int)app.report.rows[i].level!=level)){ continue; }
        if(*query && !StrStrIW(row->name,query) && !StrStrIW(row->detail,query) &&
           !StrStrIW(row->address,query) && !StrStrIW(g->name,query) && !StrStrIW(row->level,query)){ continue; }
        if(!g->matched){ app.view[app.view_count++]=(view_row){SIZE_MAX,row->group}; }
        ++g->matched;++app.matched;
        if(!g->collapsed){ app.view[app.view_count++]=(view_row){i,row->group}; }
    }
    if(app.view_count){ qsort(app.view,app.view_count,sizeof(*app.view),compare_view); }
    ListView_SetItemState(app.table,-1,0,LVIS_SELECTED|LVIS_FOCUSED);
    ListView_SetItemCountEx(app.table,(int)app.view_count,LVSICF_NOSCROLL);
    SetWindowTextW(app.detail,L"");
    InvalidateRect(app.table,NULL,TRUE);status();
}
static int index_report(void){
    size_t i,g;
    app.rows=(display_row *)calloc(app.report.count+1,sizeof(*app.rows));
    app.groups=(group *)calloc(app.report.count+1,sizeof(*app.groups));
    app.view=(view_row *)calloc(app.report.count*2+1,sizeof(*app.view));
    if(!app.rows || !app.groups || !app.view){ return 0; }
    for(i=0;i<app.report.count;++i){
        ps_row *r=&app.report.rows[i];display_row *d=&app.rows[i];
        for(g=0;g<app.group_count;++g){ if(!strcmp(app.groups[g].kind,r->kind)){ break; } }
        if(g==app.group_count){
            app.groups[g].kind=r->kind;app.groups[g].name=wide(!strcmp(r->kind,"iat") ? "Import pointers" : !strcmp(r->kind,"tls") ? "TLS" : r->kind);
            if(!app.groups[g].name){ return 0; }
            CharUpperBuffW(app.groups[g].name,1);++app.group_count;
        }
        ++app.groups[g].count;d->group=g;d->name=wide(r->name);d->detail=wide(r->detail);
        if(!d->name || !d->detail){ return 0; }
        swprintf(d->address,24,L"0x%016llx",(unsigned long long)r->address);
        swprintf(d->size,32,L"%llu",(unsigned long long)r->size);
        MultiByteToWideChar(CP_UTF8,0,ps_level_name(r->level),-1,d->level,20);
    }
    return 1;
}
static void tree(void){
    TVINSERTSTRUCTW item;
    HTREEITEM root;
    size_t i;
    app.ready=0;TreeView_DeleteAllItems(app.tree);ZeroMemory(&item,sizeof(item));
    item.hParent=TVI_ROOT;item.hInsertAfter=TVI_LAST;item.item.mask=TVIF_TEXT|TVIF_PARAM;
    item.item.pszText=L"All records";item.item.lParam=-1;
    root=TreeView_InsertItem(app.tree,&item);
    for(i=0;i<app.group_count;++i){
        wchar_t name[256];
        swprintf(name,256,L"%ls (%zu)",app.groups[i].name,app.groups[i].count);
        item.hParent=root;item.item.pszText=name;item.item.lParam=(LPARAM)i;
        TreeView_InsertItem(app.tree,&item);
    }
    TreeView_Expand(app.tree,root,TVE_EXPAND);TreeView_SelectItem(app.tree,root);app.ready=1;
}
static size_t selected(void){
    int i=ListView_GetNextItem(app.table,-1,LVNI_SELECTED);
    return i>=0 && (size_t)i<app.view_count ? app.view[(size_t)i].row : SIZE_MAX;
}
static void details(void){
    size_t i=selected(),n,j,used;
    wchar_t *text;
    display_row *d;
    if(i==SIZE_MAX){ SetWindowTextW(app.detail,L"");return; }
    d=&app.rows[i];n=wcslen(d->detail)+wcslen(d->name)+512;
    text=(wchar_t *)calloc(n,sizeof(*text));
    if(!text){ message(L"Cannot allocate detail text.");return; }
    {
        int length=swprintf(text,n,L"%ls  |  %ls  |  %ls  |  %ls bytes\r\n%ls\r\n\r\n",
                            app.groups[d->group].name,d->level,d->address,d->size,d->name);
        if(length<0){ free(text);return; }
        used=(size_t)length;
    }
    for(j=0;d->detail[j] && used+2<n;++j){
        if(d->detail[j]==L' ' && d->detail[j+1]==L'|' && d->detail[j+2]==L' '){
            text[used++]=L'\r';text[used++]=L'\n';j+=2;
        }else{ text[used++]=d->detail[j]; }
    }
    SetWindowTextW(app.detail,text);free(text);
}
static void toggle_group(int expand){
    int at=ListView_GetNextItem(app.table,-1,LVNI_SELECTED);
    if(at>=0 && (size_t)at<app.view_count && app.view[(size_t)at].row==SIZE_MAX){
        size_t g=app.view[(size_t)at].group,j;
        app.groups[g].collapsed=expand<0 ? !app.groups[g].collapsed : !expand;filter();
        for(j=0;j<app.view_count;++j){
            if(app.view[j].row==SIZE_MAX && app.view[j].group==g){
                ListView_SetItemState(app.table,(int)j,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);break;
            }
        }
    }
}
static int choose_file(wchar_t *path,int save,int html){
    OPENFILENAMEW dialog;
    ZeroMemory(&dialog,sizeof(dialog));dialog.lStructSize=sizeof(dialog);dialog.hwndOwner=app.window;
    dialog.lpstrFile=path;dialog.nMaxFile=32768;
    dialog.lpstrFilter=save ? (html ? L"HTML report\0*.html\0\0" : L"JSON report\0*.json\0\0") :
        L"PE files\0*.exe;*.dll;*.sys;*.pe\0All files\0*.*\0\0";
    dialog.Flags=OFN_EXPLORER|OFN_NOCHANGEDIR|OFN_PATHMUSTEXIST|(save ? 0 : OFN_FILEMUSTEXIST);
    dialog.lpstrDefExt=save ? (html ? L"html" : L"json") : NULL;
    return save ? GetSaveFileNameW(&dialog)!=0 : GetOpenFileNameW(&dialog)!=0;
}
static void browse(HWND edit){
    wchar_t *path=(wchar_t *)calloc(32768,sizeof(*path));
    if(path){ GetWindowTextW(edit,path,32768);if(choose_file(path,0,0)){ SetWindowTextW(edit,path); }free(path); }
}
static void export_report(int html){
    wchar_t *path;
    char *name;
    if(!app.ready){ return; }
    path=(wchar_t *)calloc(32768,sizeof(*path));if(!path){ error(L"Not enough memory.");return; }
    wcscpy(path,html ? L"report.html" : L"report.json");
    if(choose_file(path,1,html)){
        name=utf8(path);
        if(!name || !ps_export(&app.report,html ? NULL : name,html ? name : NULL)){
            error(L"Cannot create report. Choose a new filename; existing files are preserved.");
        }else{ message(L"Report saved. Export includes every analysis record, regardless of the current filter."); }
        free(name);
    }
    free(path);
}
static void copy_details(void){
    int n=GetWindowTextLengthW(app.detail);
    HGLOBAL memory;
    wchar_t *p;
    if(!n || !OpenClipboard(app.window)){ return; }
    memory=GlobalAlloc(GMEM_MOVEABLE,((size_t)n+1)*sizeof(wchar_t));
    p=memory ? (wchar_t *)GlobalLock(memory) : NULL;
    if(p){
        GetWindowTextW(app.detail,p,n+1);GlobalUnlock(memory);
        if(!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT,memory)){ GlobalFree(memory); }
    }else if(memory){ GlobalFree(memory); }
    CloseClipboard();
}
static unsigned __stdcall analyze(void *argument){
    job *j=(job *)argument;
    ps_report_init(&j->report,j->mode==3 ? "all accessible processes" : j->first);
    if(j->mode>=2){
        ps_scan_options options={0};
        options.all=j->mode==3;options.pid=options.all ? 0 : (uint32_t)strtoul(j->first,NULL,10);
        options.module=*j->module ? j->module : NULL;
        options.reference=*j->second ? j->second : NULL;
        ps_scan(&j->report,&options);
    }else{
        size_t n=0,m=0;char why[256];
        uint8_t *a=ps_read_file(j->first,&n,why,sizeof(why)),*b=NULL;
        ps_pe pa,pb;
        if(!a || !ps_pe_parse(&pa,a,n,why,sizeof(why))){ ps_emit(&j->report,"input",PS_ERROR,j->first,0,n,"%s",why); }
        else if(j->mode==1){
            b=ps_read_file(j->second,&m,why,sizeof(why));
            if(!b || !ps_pe_parse(&pb,b,m,why,sizeof(why))){ ps_emit(&j->report,"input",PS_ERROR,j->second,0,m,"%s",why); }
            else{ ps_pe_diff(&pa,&pb,&j->report); }
        }else{ ps_pe_report(&pa,&j->report); }
        free(a);free(b);
    }
    PostMessageW(j->window,WM_RESULT,0,0);return 0;
}
static void start(void){
    job *j;
    if(app.thread){ return; }
    j=(job *)calloc(1,sizeof(*j));if(!j){ error(L"Not enough memory.");return; }
    j->mode=(int)SendMessageW(app.mode,CB_GETCURSEL,0,0);
    j->first=input(app.first);j->second=input(app.second);j->module=input(app.module);j->window=app.window;
    if(!j->first || !j->second || !j->module){ free_job(j);error(L"Invalid Unicode input or not enough memory.");return; }
    if(j->mode==0){ *j->second='\0'; }
    if(j->mode==3){ *j->second='\0'; }
    if((j->mode<3 && !*j->first) || (j->mode==1 && !*j->second)){
        free_job(j);error(L"Select the input file(s), or enter a process ID.");return;
    }
    if(j->mode==2){
        char *end;unsigned long pid;
        errno=0;pid=strtoul(j->first,&end,10);
        if(*j->first<'0' || *j->first>'9' || *end || errno || !pid || pid>UINT32_MAX || (*j->second && !*j->module)){
            free_job(j);error(L"Enter a positive 32-bit PID. An explicit reference also requires a module filter.");return;
        }
    }
    app.pending=j;app.thread=(HANDLE)_beginthreadex(NULL,0,analyze,j,0,NULL);
    if(!app.thread){ app.pending=NULL;free_job(j);error(L"Cannot start analysis worker.");return; }
    EnableWindow(app.run,FALSE);message(L"Analysis running. Results will appear when complete.");
}
static void mode_changed(void){
    int mode=(int)SendMessageW(app.mode,CB_GETCURSEL,0,0);
    SetWindowTextW(app.labels[0],mode>=2 ? L"PID" : L"Input");
    SetWindowTextW(app.labels[1],mode==1 ? L"After file" : L"Reference");
    EnableWindow(app.first,mode!=3);EnableWindow(app.browse1,mode<2);
    EnableWindow(app.second,mode==1 || mode==2);EnableWindow(app.browse2,mode==1 || mode==2);
    EnableWindow(app.module,mode>=2);
}
static void smoke(void){
    char *path;
    size_t total=app.view_count;
    app.exit_code=1;
    if(!app.report.count || !app.rows || ListView_GetItemCount(app.table)!=(int)total){ goto done; }
    SetWindowTextW(app.search,L"ImageBase");filter();
    if(app.matched!=1 || app.view_count!=2){ goto done; }
    ListView_SetItemState(app.table,1,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);details();
    if(GetWindowTextLengthW(app.detail)==0){ goto done; }
    SetWindowTextW(app.search,L"");filter();
    if(app.view_count!=total){ goto done; }
    app.groups[0].collapsed=1;filter();
    if(app.view_count>=total){ goto done; }
    app.groups[0].collapsed=0;filter();
    path=utf8(app.smoke_export);
    if(path && ps_export(&app.report,path,NULL)){ app.exit_code=0; }
    free(path);
done:
    PostMessageW(app.window,WM_CLOSE,0,0);
}
static void receive(void){
    job *j=app.pending;
    WaitForSingleObject(app.thread,INFINITE);CloseHandle(app.thread);app.thread=NULL;app.pending=NULL;
    if(app.closing){ free_job(j);DestroyWindow(app.window);return; }
    app.ready=0;ListView_SetItemCountEx(app.table,0,0);free_view();ps_report_free(&app.report);
    app.report=j->report;ZeroMemory(&j->report,sizeof(j->report));free_job(j);
    EnableWindow(app.run,TRUE);app.category=-1;
    if(!index_report()){
        free_view();message(L"Not enough memory to display results. The analysis could not be displayed.");
        if(app.smoke){ app.exit_code=1;PostMessageW(app.window,WM_CLOSE,0,0); }
        return;
    }
    tree();filter();
    {
        wchar_t *subject=wide(app.report.subject ? app.report.subject : "");
        if(subject){
            size_t n=wcslen(subject)+32;wchar_t *title=(wchar_t *)calloc(n,sizeof(*title));
            if(title){ swprintf(title,n,L"pe analyzer - %ls",subject);SetWindowTextW(app.window,title);free(title); }free(subject);
        }
    }
    EnableWindow(app.json,TRUE);EnableWindow(app.html,TRUE);
    if(app.smoke){ smoke(); }
}
static LRESULT draw_table(NMLVCUSTOMDRAW *draw){
    if(draw->nmcd.dwDrawStage==CDDS_PREPAINT){ return CDRF_NOTIFYITEMDRAW; }
    if(draw->nmcd.dwDrawStage==CDDS_ITEMPREPAINT){
        size_t i=(size_t)draw->nmcd.dwItemSpec;
        RECT r=draw->nmcd.rc;
        HDC dc=draw->nmcd.hdc;
        view_row *v;
        int column,x=-GetScrollPos(app.table,SB_HORZ),picked,saved;
        HBRUSH brush;
        if(i>=app.view_count){ return CDRF_SKIPDEFAULT; }
        saved=SaveDC(dc);
        v=&app.view[i];picked=(ListView_GetItemState(app.table,(int)i,LVIS_SELECTED)&LVIS_SELECTED)!=0;
        brush=CreateSolidBrush(picked ? SELECTED : v->row==SIZE_MAX ? PANEL : BG);
        FillRect(dc,&r,brush);DeleteObject(brush);SetBkMode(dc,TRANSPARENT);
        for(column=0;column<5;++column){
            wchar_t title[256];const wchar_t *s=L"";
            RECT cell=r;int width=ListView_GetColumnWidth(app.table,column);
            cell.left=x;cell.right=x+width;
            if(v->row==SIZE_MAX){
                if(column==0){ swprintf(title,256,L"%ls %ls",app.groups[v->group].collapsed ? L"+" : L"-",app.groups[v->group].name);s=title; }
                else if(column==1){ swprintf(title,256,L"%zu %ls",app.groups[v->group].matched,app.groups[v->group].matched==1 ? L"record" : L"records");s=title; }
            }else{
                display_row *d=&app.rows[v->row];
                s=column==0 ? d->name : column==1 ? d->detail : column==2 ? d->address : column==3 ? d->size : d->level;
            }
            SetTextColor(dc,column==4 && !picked ? MUTED : FG);
            SelectObject(dc,v->row==SIZE_MAX ? app.bold : column==2 || column==3 ? app.mono : app.font);
            cell.left+=px(column==0 && v->row!=SIZE_MAX ? 22 : 7);cell.right-=px(6);
            DrawTextW(dc,s,-1,&cell,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS|DT_NOPREFIX|(column==3 ? DT_RIGHT : DT_LEFT));
            x+=width;
            SetDCPenColor(dc,LINE);SelectObject(dc,GetStockObject(DC_PEN));MoveToEx(dc,x-1,r.top,NULL);LineTo(dc,x-1,r.bottom);
        }
        SetDCPenColor(dc,LINE);SelectObject(dc,GetStockObject(DC_PEN));MoveToEx(dc,r.left,r.bottom-1,NULL);LineTo(dc,r.right,r.bottom-1);
        RestoreDC(dc,saved);return CDRF_SKIPDEFAULT;
    }
    return CDRF_DODEFAULT;
}
static LRESULT notify(NMHDR *header){
    if(header->hwndFrom==ListView_GetHeader(app.table) && header->code==NM_CUSTOMDRAW){
        NMCUSTOMDRAW *d=(NMCUSTOMDRAW *)header;
        if(d->dwDrawStage==CDDS_PREPAINT){ return CDRF_NOTIFYITEMDRAW; }
        if(d->dwDrawStage==CDDS_ITEMPREPAINT){
            wchar_t name[96];HDITEMW item;RECT r=d->rc;int saved=SaveDC(d->hdc);
            ZeroMemory(&item,sizeof(item));item.mask=HDI_TEXT;item.pszText=name;item.cchTextMax=96;
            Header_GetItem(header->hwndFrom,(int)d->dwItemSpec,&item);
            FillRect(d->hdc,&r,app.panel);SetBkMode(d->hdc,TRANSPARENT);SetTextColor(d->hdc,FG);SelectObject(d->hdc,app.font);
            r.left+=px(7);DrawTextW(d->hdc,name,-1,&r,DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX);
            RestoreDC(d->hdc,saved);return CDRF_SKIPDEFAULT;
        }
    }
    if(header->hwndFrom==app.table){
        if(header->code==NM_CUSTOMDRAW){ return draw_table((NMLVCUSTOMDRAW *)header); }
        if(header->code==LVN_GETDISPINFOW){
            NMLVDISPINFOW *d=(NMLVDISPINFOW *)header;
            if(d->item.iItem>=0 && (size_t)d->item.iItem<app.view_count && (d->item.mask&LVIF_TEXT)){
                view_row *v=&app.view[(size_t)d->item.iItem];
                const wchar_t *s=app.groups[v->group].name;
                if(v->row!=SIZE_MAX){
                    display_row *row=&app.rows[v->row];
                    s=d->item.iSubItem==0 ? row->name : d->item.iSubItem==1 ? row->detail :
                      d->item.iSubItem==2 ? row->address : d->item.iSubItem==3 ? row->size : row->level;
                }
                lstrcpynW(d->item.pszText,s,d->item.cchTextMax);
            }
        }else if(header->code==LVN_ITEMCHANGED){ if(app.ready){ details(); } }
        else if(header->code==NM_CLICK || header->code==NM_DBLCLK){ toggle_group(-1); }
        else if(header->code==LVN_KEYDOWN){
            WORD key=((NMLVKEYDOWN *)header)->wVKey;
            if(key==VK_RETURN || key==VK_SPACE){ toggle_group(-1); }
            if(key==VK_LEFT || key==VK_RIGHT){ toggle_group(key==VK_RIGHT); }
            if(key=='C' && (GetKeyState(VK_CONTROL)&0x8000)){ copy_details(); }
        }else if(header->code==LVN_COLUMNCLICK){
            int col=((NMLISTVIEW *)header)->iSubItem;
            app.descending=app.sort_column==col ? !app.descending : 0;app.sort_column=col;filter();
        }
    }
    if(header->hwndFrom==app.tree){
        if(header->code==TVN_SELCHANGEDW && app.ready){ app.category=(int)((NMTREEVIEWW *)header)->itemNew.lParam;filter(); }
        if(header->code==NM_CUSTOMDRAW){
            NMTVCUSTOMDRAW *d=(NMTVCUSTOMDRAW *)header;
            if(d->nmcd.dwDrawStage==CDDS_PREPAINT){ return CDRF_NOTIFYITEMDRAW; }
            if(d->nmcd.dwDrawStage==CDDS_ITEMPREPAINT){
                d->clrText=FG;d->clrTextBk=(d->nmcd.uItemState&CDIS_SELECTED) ? SELECTED : BG;
                d->nmcd.uItemState&=~(UINT)CDIS_SELECTED;return CDRF_NEWFONT;
            }
        }
    }
    return 0;
}
static void create_controls(void){
    const wchar_t *columns[]={L"Name",L"Value",L"Address / offset",L"Bytes",L"Status"};
    const wchar_t *levels[]={L"All statuses",L"Info",L"Change",L"Review",L"Error",L"Unavailable"};
    int i;
    app.mode=control(L"COMBOBOX",L"",WS_TABSTOP|CBS_DROPDOWNLIST,ID_MODE);
    for(i=0;i<4;++i){ const wchar_t *modes[]={L"Inspect file",L"Compare files",L"Scan process",L"Scan all processes"};SendMessageW(app.mode,CB_ADDSTRING,0,(LPARAM)modes[i]); }
    SendMessageW(app.mode,CB_SETCURSEL,0,0);
    app.first=control(L"EDIT",L"",WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,ID_FIRST);
    app.second=control(L"EDIT",L"",WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,ID_SECOND);
    app.module=control(L"EDIT",L"",WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,ID_MODULE);
    app.browse1=button(L"...",ID_BROWSE1);app.browse2=button(L"...",ID_BROWSE2);app.run=button(L"Analyze",ID_RUN);
    app.json=button(L"Save JSON",ID_JSON);app.html=button(L"Save HTML",ID_HTML);
    app.search=control(L"EDIT",L"",WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,ID_SEARCH);
    SendMessageW(app.search,EM_SETLIMITTEXT,1024,0);
    SendMessageW(app.first,EM_SETLIMITTEXT,32767,0);SendMessageW(app.second,EM_SETLIMITTEXT,32767,0);
    SendMessageW(app.module,EM_SETLIMITTEXT,32767,0);
    app.level=control(L"COMBOBOX",L"",WS_TABSTOP|CBS_DROPDOWNLIST,ID_LEVEL);
    for(i=0;i<6;++i){ SendMessageW(app.level,CB_ADDSTRING,0,(LPARAM)levels[i]); }
    SendMessageW(app.level,CB_SETCURSEL,0,0);
    app.expand=button(L"Expand all",ID_EXPAND);app.collapse=button(L"Collapse all",ID_COLLAPSE);app.copy=button(L"Copy details",ID_COPY);
    app.tree=control(WC_TREEVIEWW,L"",WS_TABSTOP|TVS_HASBUTTONS|TVS_LINESATROOT|TVS_SHOWSELALWAYS,ID_TREE);
    TreeView_SetBkColor(app.tree,BG);TreeView_SetTextColor(app.tree,FG);TreeView_SetLineColor(app.tree,LINE);
    app.table=control(WC_LISTVIEWW,L"",WS_TABSTOP|LVS_REPORT|LVS_OWNERDATA|LVS_SINGLESEL|LVS_SHOWSELALWAYS|LVS_SHAREIMAGELISTS,ID_TABLE);
    ListView_SetExtendedListViewStyle(app.table,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
    ListView_SetBkColor(app.table,BG);ListView_SetTextBkColor(app.table,BG);ListView_SetTextColor(app.table,FG);
    SetWindowTheme(ListView_GetHeader(app.table),L"",L"");
    for(i=0;i<5;++i){
        LVCOLUMNW col;const int widths[]={240,470,170,75,110};
        ZeroMemory(&col,sizeof(col));col.mask=LVCF_TEXT|LVCF_WIDTH;col.pszText=(wchar_t *)columns[i];col.cx=px(widths[i]);
        ListView_InsertColumn(app.table,i,&col);
    }
    app.detail_label=control(L"STATIC",L"Details / byte preview",SS_LEFT,0);
    app.detail=control(L"EDIT",L"Select a record to inspect its complete value.",WS_TABSTOP|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL|ES_AUTOHSCROLL|WS_HSCROLL,ID_DETAIL);
    SendMessageW(app.detail,EM_SETLIMITTEXT,100000,0);
    app.status=control(L"STATIC",L"Open a PE file or enter a PID. Analysis is read-only.",SS_LEFT,0);
    { const wchar_t *names[]={L"Input",L"Reference",L"Module",L"Find",L"Ctrl+O  /  Ctrl+F"};
      for(i=0;i<5;++i){ app.labels[i]=control(L"STATIC",names[i],SS_LEFT,0); } }
    EnableWindow(app.json,FALSE);EnableWindow(app.html,FALSE);mode_changed();fonts();
    DragAcceptFiles(app.window,TRUE);
}
static LRESULT CALLBACK window_proc(HWND window,UINT msg,WPARAM w,LPARAM l){
    switch(msg){
    case WM_CREATE:
        app.window=window;app.dpi=GetDpiForWindow(window);create_controls();return 0;
    case WM_SIZE: layout();return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)l)->ptMinTrackSize.x=px(950);((MINMAXINFO *)l)->ptMinTrackSize.y=px(530);return 0;
    case WM_DPICHANGED:
        { int i;UINT old=app.dpi;app.dpi=HIWORD(w);
          for(i=0;i<5;++i){ ListView_SetColumnWidth(app.table,i,MulDiv(ListView_GetColumnWidth(app.table,i),(int)app.dpi,(int)old)); } }
        fonts();
        { RECT *r=(RECT *)l;SetWindowPos(window,NULL,r->left,r->top,r->right-r->left,r->bottom-r->top,SWP_NOZORDER|SWP_NOACTIVATE); }
        return 0;
    case WM_ERASEBKGND:
        { RECT r;GetClientRect(window,&r);FillRect((HDC)w,&r,app.background); }return 1;
    case WM_PAINT:
        { PAINTSTRUCT paint;RECT r;HDC dc=BeginPaint(window,&paint);
          GetClientRect(window,&r);r.left=px(191);r.top=r.bottom-px(app.split+27);r.bottom=r.top+px(3);
          FillRect(dc,&r,app.panel);EndPaint(window,&paint); }return 0;
    case WM_SETCURSOR:
        if(LOWORD(l)==HTCLIENT){
            POINT p;RECT r;GetCursorPos(&p);ScreenToClient(window,&p);GetClientRect(window,&r);
            if(p.x>px(190) && abs(p.y-(r.bottom-px(app.split+25)))<px(7)){
                SetCursor(LoadCursorW(NULL,IDC_SIZENS));return TRUE;
            }
        }break;
    case WM_CTLCOLORSTATIC:case WM_CTLCOLOREDIT:case WM_CTLCOLORLISTBOX:
        SetTextColor((HDC)w,IsWindowEnabled((HWND)l) ? FG : MUTED);SetBkColor((HDC)w,BG);return (LRESULT)app.background;
    case WM_DRAWITEM:
        { DRAWITEMSTRUCT *d=(DRAWITEMSTRUCT *)l;RECT r=d->rcItem;wchar_t text[128];int saved;
          if(d->CtlType!=ODT_BUTTON){ break; }
          saved=SaveDC(d->hDC);
          FillRect(d->hDC,&r,app.panel);SetDCPenColor(d->hDC,(d->itemState&ODS_FOCUS) ? FG : LINE);
          SelectObject(d->hDC,GetStockObject(DC_PEN));SelectObject(d->hDC,GetStockObject(NULL_BRUSH));Rectangle(d->hDC,r.left,r.top,r.right,r.bottom);
          GetWindowTextW(d->hwndItem,text,128);SetBkMode(d->hDC,TRANSPARENT);SelectObject(d->hDC,app.font);
          SetTextColor(d->hDC,(d->itemState&ODS_DISABLED) ? RGB(105,105,105) : FG);
          if(d->itemState&ODS_SELECTED){ OffsetRect(&r,1,1); }
          DrawTextW(d->hDC,text,-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);RestoreDC(d->hDC,saved);return TRUE; }
    case WM_NOTIFY: return notify((NMHDR *)l);
    case WM_COMMAND:
        switch(LOWORD(w)){
        case ID_MODE: if(HIWORD(w)==CBN_SELCHANGE){ mode_changed(); }break;
        case ID_BROWSE1: browse(app.first);break;
        case ID_BROWSE2: browse(app.second);break;
        case ID_RUN: start();break;
        case ID_JSON: export_report(0);break;
        case ID_HTML: export_report(1);break;
        case ID_COPY: copy_details();break;
        case ID_SEARCH: if(HIWORD(w)==EN_CHANGE){ SetTimer(window,1,120,NULL); }break;
        case ID_LEVEL: if(HIWORD(w)==CBN_SELCHANGE){ filter(); }break;
        case ID_EXPAND:case ID_COLLAPSE:
            { size_t i;for(i=0;i<app.group_count;++i){ app.groups[i].collapsed=LOWORD(w)==ID_COLLAPSE; }filter(); }break;
        }
        return 0;
    case WM_TIMER: KillTimer(window,1);filter();return 0;
    case WM_LBUTTONDOWN:
        { RECT r;int y;GetClientRect(window,&r);y=r.bottom-px(app.split+25);
          if(GET_X_LPARAM(l)>px(190) && abs(GET_Y_LPARAM(l)-y)<px(7)){ app.dragging=1;SetCapture(window); } }return 0;
    case WM_MOUSEMOVE:
        if(app.dragging){ RECT r;GetClientRect(window,&r);app.split=MulDiv(r.bottom-GET_Y_LPARAM(l),96,(int)app.dpi)-25;layout(); }return 0;
    case WM_LBUTTONUP: app.dragging=0;ReleaseCapture();return 0;
    case WM_DROPFILES:
        { wchar_t *path=(wchar_t *)calloc(32768,sizeof(wchar_t));
          if(path && !app.thread && DragQueryFileW((HDROP)w,0,path,32768)){
              SendMessageW(app.mode,CB_SETCURSEL,0,0);mode_changed();SetWindowTextW(app.first,path);start();
          }free(path);DragFinish((HDROP)w); }return 0;
    case WM_RESULT: receive();return 0;
    case WM_CLOSE:
        if(app.thread){ app.closing=1;ShowWindow(window,SW_HIDE); }else{ DestroyWindow(window); }return 0;
    case WM_DESTROY: PostQuitMessage(app.exit_code);return 0;
    }
    return DefWindowProcW(window,msg,w,l);
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE previous,LPWSTR command,int show){
    INITCOMMONCONTROLSEX common={sizeof(common),ICC_LISTVIEW_CLASSES|ICC_TREEVIEW_CLASSES};
    WNDCLASSEXW cls;MSG msg;int argc=0;wchar_t **argv;
    (void)previous;(void)command;
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    app.dpi=96;app.split=190;app.category=-1;app.sort_column=-1;
    app.background=CreateSolidBrush(BG);app.panel=CreateSolidBrush(PANEL);fonts();
    InitCommonControlsEx(&common);ZeroMemory(&cls,sizeof(cls));cls.cbSize=sizeof(cls);cls.hInstance=instance;
    cls.lpfnWndProc=window_proc;cls.lpszClassName=L"PEAnalyzerWindow";cls.hCursor=LoadCursorW(NULL,IDC_ARROW);
    cls.hIcon=LoadIconW(NULL,IDI_APPLICATION);cls.hbrBackground=app.background;
    if(!RegisterClassExW(&cls)){ return 1; }
    app.window=CreateWindowExW(WS_EX_CONTROLPARENT,cls.lpszClassName,L"pe analyzer",WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT,CW_USEDEFAULT,1280,820,NULL,NULL,instance,NULL);
    if(!app.window){ return 1; }
    { BOOL dark=TRUE;DwmSetWindowAttribute(app.window,20,&dark,sizeof(dark)); }
    ShowWindow(app.window,show);UpdateWindow(app.window);
    argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(argv && argc==4 && !wcscmp(argv[1],L"--smoke")){
        app.smoke=1;app.smoke_export=argv[3];SetWindowTextW(app.first,argv[2]);start();
    }else if(argv && argc==2){ SetWindowTextW(app.first,argv[1]);start(); }
    while(GetMessageW(&msg,NULL,0,0)>0){
        if(msg.message==WM_KEYDOWN && (GetKeyState(VK_CONTROL)&0x8000)){
            if(msg.wParam=='F'){ SetFocus(app.search);SendMessageW(app.search,EM_SETSEL,0,-1);continue; }
            if(msg.wParam=='O' && !app.thread){ SendMessageW(app.mode,CB_SETCURSEL,0,0);mode_changed();browse(app.first);continue; }
        }
        if(!IsDialogMessageW(app.window,&msg)){ TranslateMessage(&msg);DispatchMessageW(&msg); }
    }
    if(app.thread){ WaitForSingleObject(app.thread,INFINITE);CloseHandle(app.thread);free_job(app.pending); }
    LocalFree(argv);free_view();ps_report_free(&app.report);
    if(app.row_height){ ImageList_Destroy(app.row_height); }
    DeleteObject(app.font);DeleteObject(app.mono);DeleteObject(app.bold);DeleteObject(app.background);DeleteObject(app.panel);
    return app.exit_code;
}
