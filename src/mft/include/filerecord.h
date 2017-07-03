#ifndef _INCLUDE_FILERECORD_H
#define _INCLUDE_FILERECORD_H

#include <cstdint>
#include <vector>

#include "mft.h"
#include "attribute.h"

#ifndef _WIN32
#define MAX_PATH 260
#endif

#pragma pack(1)

extern bool lt;
extern char tzstr[16];
extern std::string computername;

using namespace std;

struct FILE_RECORD {
  char signature[4];
  uint16_t fixup_offset;
  uint16_t fixup_count;
  uint64_t lsn;
  uint16_t seq_val;
  uint16_t link_cnt;
  uint16_t fattr_offset;
  uint16_t flags;
  uint32_t used_size;
  uint32_t alloc_size;
  uint64_t baserecord_ref;
  uint16_t next_attrid; char _padd[2];

  uint32_t record_num;
  uint16_t fixup;
};


enum FILERECORD_FLAGS {
  FILE_DELETED = 0b00000000,
  FILE_ALLOCATED = 0b00010000,
  DIRECTORY_DELETED = 0b00100000,
  DIRECTORY_ALLOCATED = 0b00110000,
};

struct CSVRecord {
  string filename;
  string pathname;
  uint64_t fileid;
  uint16_t flag;
  uint64_t filesize;
  uint64_t created;
  uint64_t modified;
  uint64_t recordchanged;
  uint64_t accessed;
  uint64_t created_fn;
  uint64_t modified_fn;
  uint64_t recordchanged_fn;
  uint64_t accessed_fn;
  uint32_t owner; // TODO:
  string misc;
  int ns_tmp; // for calc: which FILE_NAME to take
};

struct RESIDENT_DATA {
  char *name;
  unsigned int len;
  unsigned char *data;
};


class MFT;

class FileRecord {
public:
  enum ERROR {
    ERROR_EOF = -1,
    ERROR_BADSIGNATURE = -2,
  };

private:
  uint16_t bytes_per_sector;
  uint32_t record_size;
  bool parsed;
  MFT *mft;
  FILE *fp_head;
  uint64_t offset;
  unsigned char *data;

public:
  uint32_t record_num;
  FILE_RECORD record;
  CSVRecord csvrecord;
  vector<ATTR> attrs;
  string fname;
  vector<RESIDENT_DATA*> resident_data;

  // info

public:
  FileRecord(MFT*, uint64_t);
  int ReadRecord();
  int VerifyFixup();

  // for normal dump
  int ParseRecord(bool dump=false);
  int ParseAttrs(unsigned char*, bool dump=false);
  int ParseAttr(ATTR, unsigned char*, bool dump=false);

  // for CSV dump
  int ParseRecord_csv();
  int ParseAttrs_csv(unsigned char*);
  int ParseAttr_csv(ATTR, unsigned char*);

  void printFileName(uint64_t);
  string getFileName(uint64_t);
};

#endif // _INCLUDE_FILERECORD_H
