#ifndef _INCLUDE_MFT_H
#define _INCLUDE_MFT_H

#include <cstdint>
#include <cstdio>

#include <vector>
#include <map>

#include "filerecord.h"
#include "attribute.h"

#pragma pack(1)


using namespace std;


class FileRecord;

class MFT {
public:
  uint16_t bytes_per_sector;
  uint8_t sectors_per_clustor;
  uint8_t clustors_per_filerecord;
  uint32_t record_size;
  FILE *fp_head;
  vector<uint32_t> record_nums;
  map<uint32_t, uint64_t> record_table; // record_num to offset
  map<uint32_t, string> filename;
  map<uint32_t, uint32_t> ref_table;

public:
  MFT(char*, int);
  MFT(char*, 
      uint16_t bytes_per_sector=512, 
      uint8_t sectors_per_clustor=2, 
      uint8_t clustors_per_filerecord=1);
  int parse(uint32_t, FileRecord*, bool=true);
  int parse_csv(uint32_t, FileRecord*);
};

#endif // _INCLUDE_MFT_H
