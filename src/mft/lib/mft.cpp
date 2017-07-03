#include "mft.h"

#include <cstdio>
#include <cstdlib>



MFT::MFT(char *data, int record_size) {
  // TODO
}


MFT::MFT(char *fname, uint16_t _bytes_per_sector, uint8_t _sectors_per_clustor, uint8_t _clustors_per_filerecord) {

  unsigned char *r;
  uint32_t record;
  uint64_t offset = 0;
  int readbytes;
  FILE *fp;

  if((fp_head = fopen(fname, "rb")) == NULL) {
    perror("fopen");
    return;
  }
  fp = fp_head;

  bytes_per_sector = _bytes_per_sector;
  sectors_per_clustor = _sectors_per_clustor;
  clustors_per_filerecord = _clustors_per_filerecord;
  record_size = bytes_per_sector * sectors_per_clustor * clustors_per_filerecord;

  while(1) {
    FileRecord fr = FileRecord(this, offset);

    int res = fr.ReadRecord();
    if(res) {
      if(res == FileRecord::ERROR_EOF) break;

      offset += record_size;
      continue;
    }

    record_nums.push_back(fr.record_num);
    record_table[fr.record_num] = offset;
    offset += record_size;
  }
}


int MFT::parse(uint32_t num, FileRecord* fr, bool dump) {
  if(record_table.find(num) == record_table.end()) {
    return -1;
  }

  fr = new FileRecord(this, record_table[num]);

  if(fr->ParseRecord(dump)) {
    return -1;
  }

  return 0;
}


int MFT::parse_csv(uint32_t num, FileRecord* fr) {
  if(record_table.find(num) == record_table.end()) {
    return -1;
  }

  fr = new FileRecord(this, record_table[num]);

  // clear calc val
  (fr->csvrecord).ns_tmp = -1;

  if(fr->ParseRecord_csv()) {
    return -1;
  }

  return 0;
}
