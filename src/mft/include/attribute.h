#ifndef _INCLUDE_ATTRIBUTE_H
#define _INCLUDE_ATTRIBUTE_H

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#pragma pack(1)

const unsigned char END_OF_ATTR[4] = {0xff, 0xff, 0xff, 0xff};


// ATTRIBUTE

enum ATTRTYPEID {
  ATTRTYPEID_STANDARD_INFORMATION  = 0x10,
  ATTRTYPEID_ATTRIBUTE_LIST        = 0x20,
  ATTRTYPEID_FILE_NAME             = 0x30,
  ATTRTYPEID_DATA                  = 0x80,
};



// $STANDARD_INFORMATION

enum FILE_FLAGS {
  READ_ONLY     = 0x0001,
  HIDDEN        = 0x0002,
  SYSTEM        = 0x0004,
  ARCHIVE       = 0x0020,
  DEVICE        = 0x0040,
  NORMAL        = 0x0080,
  TEMPORARY     = 0x0100,
  SPARSE_FILE   = 0x0200,
  REPARSE_POINT = 0x0400,
  COMPRESSED    = 0x0800,
  OFFLINE       = 0x1000,
  NOT_INDEXED   = 0x2000,
  ENCRYPTED     = 0x4000
};

struct ATTR_STANDARD_INFORMATION {
  uint64_t creationtime;
  uint64_t file_altered_time;
  uint64_t mft_altered_time;
  uint64_t file_accessed_time;
  uint32_t flags;
  uint32_t max_version;
  uint32_t version;
  uint32_t class_id;
  uint32_t owner_id;
  uint32_t security_id;
  uint64_t quota_charged;
  uint64_t usn;
};



// $FILE_NAME

struct ATTR_FILE_NAME {
  uint64_t parent_ref_mft_entry:48;
  uint64_t parent_ref_mft_seq:16;
  uint64_t creationtime;
  uint64_t file_altered_time;
  uint64_t mft_altered_time;
  uint64_t file_accessed_time;
  uint64_t alloc_size;
  uint64_t real_size;
  uint32_t flags;
  uint32_t reparse_val;
  uint8_t fname_len;
  uint8_t fname_space;
  char16_t *fname;
};



// $ATTRIBUTE_LIST

struct ATTR_ATTRIBUTE_LIST {
  uint32_t attr_type;
  uint16_t entry_len;
  uint8_t name_len;
  uint8_t name_offset;
  uint64_t start_vcn;
  uint64_t attr_file_ref_record:48;
  uint64_t attr_file_ref_seq:16;
  uint8_t attr_id;
};



// ATTRIBUTE structure

struct ATTR_HEADER_BASE {
  uint32_t attr_typeid;
  uint32_t attr_len;
  uint8_t flag_nonresident;
  uint8_t name_len;
  uint16_t name_offset;
  uint16_t flags;
  uint16_t attr_id;
};

struct ATTR_HEADER_RESIDENT {
  ATTR_HEADER_BASE base;
  uint32_t size;
  uint16_t offset;
  uint8_t indx_flag;
  uint8_t _padd;
};

struct ATTR_HEADER_NONRESIDENT {
  ATTR_HEADER_BASE base;
  uint64_t vcn_start;
  uint64_t vcn_end;
  uint16_t runlist_offset;
  uint16_t compression_unit_size;
  uint32_t _unused;
  uint64_t alloc_attr_size;
  uint64_t actual_attr_size;
  uint64_t init_attr_size;
};

union ATTR_HEADER {
  ATTR_HEADER_BASE base;
  ATTR_HEADER_RESIDENT resident;
  ATTR_HEADER_NONRESIDENT nonresident;
};


union ATTR_CONTENT {
  ATTR_STANDARD_INFORMATION standard_information;
  ATTR_FILE_NAME file_name;
  ATTR_ATTRIBUTE_LIST attribute_list;
};


struct ATTR {
  ATTR_HEADER header;
  ATTR_CONTENT content;
};


#endif // _INCLUDE_ATTRIBUTE_H
