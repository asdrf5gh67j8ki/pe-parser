#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

static const int marker=7;
typedef struct { const int *relocated_pointer; uint8_t bytes[56]; } demo_block;
#ifdef _MSC_VER
#pragma section(".pstest",read,execute)
__declspec(allocate(".pstest")) __declspec(dllexport)
const demo_block ps_demo_block={&marker,{0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xc3}};
#else
/* MinGW's linker sets the executable characteristic via the section directive. */
__asm__(".section .pstest,\"xr\"\n.text");
__attribute__((section(".pstest"),dllexport))
const demo_block ps_demo_block={&marker,{0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xc3}};
#endif
__declspec(dllexport) DWORD demo_tick(void){ return GetTickCount(); }
