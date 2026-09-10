#ifndef PS_H
#define PS_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define PS_VERSION "1.1.0"
#define PS_FILE_LIMIT (128u * 1024u * 1024u)
#define PS_IMAGE_LIMIT (256u * 1024u * 1024u)
#define PS_ROW_LIMIT 100000u
#define PS_ITEM_LIMIT 65536u
#define PS_SECTIONS 96u

typedef enum { PS_INFO, PS_CHANGE, PS_WARN, PS_ERROR, PS_SKIP } ps_level;
typedef struct {
    char *kind, *name, *detail;
    uint64_t address, size;
    ps_level level;
} ps_row;
typedef struct {
    ps_row *rows;
    size_t count, capacity, string_bytes;
    unsigned levels[5];
    int failed, limited;
    char *subject;
    char started[32];
} ps_report;
typedef struct {
    char name[9];
    uint32_t va, virtual_size, raw, raw_size, flags, header;
} ps_section;
typedef struct {
    uint32_t address, size;
} ps_directory;
typedef struct {
    const uint8_t *data;
    size_t size;
    uint32_t nt, optional, section_table, entry, image_size, headers_size;
    uint32_t timestamp, checksum, file_alignment, section_alignment;
    uint16_t machine, section_count, subsystem, characteristics, dll_flags;
    int bits;
    uint64_t base;
    ps_section sections[PS_SECTIONS];
    ps_directory dirs[16];
} ps_pe;
typedef enum {
    PS_MAP_OK, PS_MAP_ZERO, PS_MAP_MISSING, PS_MAP_AMBIGUOUS,
    PS_MAP_TRUNCATED, PS_MAP_BOUNDARY
} ps_mapping;
typedef int (*ps_import_fn)(void *, const char *, const char *, uint32_t, int);
typedef struct {
    /* valid: 0 unknown, 1 known, 2 import slot, 3 normalized relocation. */
    uint8_t *bytes, *valid;
    size_t size;
    uint64_t relocations, masked;
} ps_image;
typedef struct {
    uint32_t pid;
    const char *module, *reference, *dump;
    int all;
} ps_scan_options;

uint16_t ps_u16(const uint8_t *);
uint32_t ps_u32(const uint8_t *);
uint64_t ps_u64(const uint8_t *);
void ps_w32(uint8_t *, uint32_t);
void ps_w64(uint8_t *, uint64_t);
int ps_range(uint64_t, uint64_t, uint64_t);
FILE *ps_fopen(const char *, const char *);
uint8_t *ps_read_file(const char *, size_t *, char *, size_t);
void ps_sha256(const void *, size_t, char[65]);
double ps_entropy(const uint8_t *, size_t);
void ps_hex(const uint8_t *, size_t, char *, size_t);
void ps_report_init(ps_report *, const char *);
void ps_report_free(ps_report *);
void ps_emit(ps_report *, const char *, ps_level, const char *, uint64_t, uint64_t, const char *, ...);
const char *ps_level_name(ps_level);
int ps_export(const ps_report *, const char *, const char *);
int ps_output(ps_report *, const char *, const char *, int, int);
int ps_pe_parse(ps_pe *, const uint8_t *, size_t, char *, size_t);
ps_mapping ps_pe_map(const ps_pe *, uint32_t, size_t, size_t *);
const char *ps_mapping_name(ps_mapping);
const ps_section *ps_pe_section(const ps_pe *, uint32_t);
int ps_pe_imports(const ps_pe *, ps_import_fn, void *, char *, size_t);
void ps_pe_report(const ps_pe *, ps_report *);
int ps_pe_image(const ps_pe *, uint64_t, ps_image *, char *, size_t);
int ps_pe_runtime_base(const ps_pe *, uint64_t, size_t, const uint8_t *, uint8_t *, size_t);
void ps_image_free(ps_image *);
void ps_pe_diff(const ps_pe *, const ps_pe *, ps_report *);
int ps_scan(ps_report *, const ps_scan_options *);

#endif
