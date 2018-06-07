#include "filerecord.h"
#include "utils.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <iostream>

using namespace std;


FileRecord::FileRecord(MFT* _mft, uint64_t _offset) { 
  parsed = false;
  fp_head = _mft->fp_head;
  record_size = _mft->record_size;
  offset = _offset;
  mft = _mft;

  record_num = -1;
}


int FileRecord::ReadRecord() {
  FILE *fp;
  unsigned char *p = (unsigned char*)malloc(record_size);

  fp = fp_head;
  fseek(fp, offset, SEEK_SET);
  if(fread(p, 1, record_size, fp) != record_size) {
#ifdef DEBUG
    perror("fread");
#endif
    free(p);
    return ERROR_EOF;
  }

  if(strncmp((char*)p, "FILE", 4)) {
    free(p);
    return ERROR_BADSIGNATURE;
  }
  else {
    record_num = ((FILE_RECORD*)p)->record_num;
  }

  free(p);

  return 0;
}


int FileRecord::ParseRecord(bool dump) {
  FILE *fp = fp_head;

  data = (unsigned char*)malloc(record_size);

  fseek(fp, offset, SEEK_SET);
  if(fread(data, 1, record_size, fp) != record_size) {
#ifdef DEBUG
    perror("fread");
#endif
    return ERROR_EOF;
  }

  memcpy(&(this->record), data, sizeof(FILE_RECORD));

  if(strncmp(this->record.signature, "FILE", 4)) {
    fprintf(stderr, "Bad Signature: %s\n", this->record.signature);
    return ERROR_BADSIGNATURE;
  }
  record_num = this->record.record_num;

  parsed = true;

  if(dump) {
    printf("\nRecord Number: %lu\n", this->record.record_num);
  }

  VerifyFixup();
  ParseAttrs(data+(this->record.fattr_offset), dump);

  if(dump) {
    printf("\n");
  }

  free(data);

  return 0;
}


int FileRecord::ParseAttrs(unsigned char *p, bool dump) {
  // base
  unsigned char *tmp;
  uint32_t attrid;
  uint32_t header_size;
  ATTR attr;

  // FILE_NAME
  char16_t *fname;
  uint8_t fname_len;

  if(dump) {
    printf("ATTRIBUTES:\n");
  }

  for(tmp = p; ; tmp += attr.header.base.attr_len) {
    if(!memcmp(tmp, END_OF_ATTR, 4)) break;
    memcpy(&attr, tmp, sizeof(ATTR_HEADER_BASE));

    if(!attr.header.base.flag_nonresident) { // resident
      header_size = sizeof(ATTR_HEADER_RESIDENT);
      memcpy(&attr, tmp, header_size);
    }
    else {
      header_size = sizeof(ATTR_HEADER_NONRESIDENT);
      memcpy(&attr, tmp, header_size);
    }

    if(attr.header.base.name_len) {
      if(dump) {
        printf("Attribute Name: ");
        printUTF16((char16_t*)(tmp+(attr.header.base.name_offset)), attr.header.base.name_len);
        printf("\n");
      }
    }

    ParseAttr(attr, tmp+header_size, dump);

    // this->attrs.push_back(attr);
  }

  return 0;
}


// parse each attribute (not including header)
int FileRecord::ParseAttr(ATTR attr, unsigned char *content, bool dump) {
  // base
  unsigned char *p;
  bool nonresident;
  uint32_t attrid;
  uint32_t header_size;
  uint32_t content_size;

  // FILE_NAME
  char16_t *fname;
  uint8_t fname_len;

  // for ATTRIBUTE_LIST
  FileRecord *fr;
  uint32_t ref;

  RESIDENT_DATA *resdata;


  attrid = attr.header.base.attr_typeid;

  if(!attr.header.base.flag_nonresident) {
    nonresident = false;
    header_size = sizeof(ATTR_HEADER_RESIDENT);
    content_size = attr.header.base.attr_len - sizeof(ATTR_HEADER_RESIDENT);
  }
  else {
    nonresident = true;
    header_size = sizeof(ATTR_HEADER_NONRESIDENT);
    content_size = attr.header.base.attr_len - sizeof(ATTR_HEADER_NONRESIDENT);
  }

  switch(attrid) {
    case ATTRTYPEID_STANDARD_INFORMATION:
      if(dump) {
        printf("\n  $STANDARD_INFORMATION\n");
      }

      memcpy(&(attr.content), content, sizeof(ATTR_STANDARD_INFORMATION));

      if(dump) {
        printf("    CreationTime: ");
        parse_time(attr.content.standard_information.creationtime, lt);
        printf("\n");
      }

      break;


    case ATTRTYPEID_ATTRIBUTE_LIST:
      if(!dump) break;

      printf("\n  $ATTRIBUTE_LIST (%s)\n", (nonresident?"nonresident":"resident"));

      for(unsigned char *c = content;
          c < content+content_size;
          c += attr.content.attribute_list.entry_len) {

        memcpy(&(attr.content), c, sizeof(ATTR_ATTRIBUTE_LIST));

        switch(attr.content.attribute_list.attr_type) {
          case ATTRTYPEID_STANDARD_INFORMATION:
            printf("    $STANDARD_INFORMATION\n");
            break;

          case ATTRTYPEID_FILE_NAME:
            printf("    $FILE_NAME\n");
            ref = attr.content.attribute_list.attr_file_ref_record;
            fr = new FileRecord(mft, mft->record_table[ref]);
            if(!fr->ParseRecord(false)) {
              mft->ref_table[record_num] = mft->ref_table[ref];
              mft->filename[record_num] = mft->filename[ref];
            }
            else {
#ifdef DEBUG
              fprintf(stderr, "parse error @ (%lu)", ref);
#endif
            }
            delete(fr);
            break;

          case ATTRTYPEID_DATA:
            printf("    $DATA\n");
            break;

          default:
            printf("    UNKNOWN(%x)\n", attr.content.attribute_list.attr_type);
        }

//        if(attr.content.attribute_list.name_len) {
//          printf(" %d ", attr.content.attribute_list.name_len);
//          hexdump(&(attr.content)+(attr.content.attribute_list.name_offset), 16);
//          printf("      Name: %s\n", &(attr.content)+(attr.content.attribute_list.name_offset));
//        }
//        printUTF16((char16_t *)&(attr.content)+attr.content.attribute_list.name_offset,
//            attr.content.attribute_list.name_len);
        if(attr.content.attribute_list.start_vcn) {
          printf("      VCN: %lld\n", (uint64_t)attr.content.attribute_list.start_vcn);
        }

        if(attr.content.attribute_list.attr_file_ref_record) {
          printf("      record ref: %ld\n", (uint32_t)attr.content.attribute_list.attr_file_ref_record);
        }

        if(attr.content.attribute_list.attr_file_ref_seq) {
          printf("      seq ref: %ld\n", (uint32_t)attr.content.attribute_list.attr_file_ref_seq);
        }
      }

      break;


    case ATTRTYPEID_FILE_NAME:
      if(dump) {
        printf("\n  $FILE_NAME\n");
      }

      memcpy(&(attr.content), content, sizeof(ATTR_FILE_NAME));

      fname_len = attr.content.file_name.fname_len;
      //        printf("before malloc\n");
      //        fname = (char16_t*)malloc(sizeof(char16_t)*fname_len);
      //        printf("after malloc\n");
      //        memcpy(fname, p+header_size+sizeof(ATTR_FILE_NAME)-sizeof(char16_t*), sizeof(char16_t)*fname_len);
      //        attr.content.file_name.fname = fname;

      if(dump) {
        printf("    CreationTime: ");
        parse_time(attr.content.file_name.creationtime, lt);
        printf("\n");
      }

      mft->ref_table[record_num] = attr.content.file_name.parent_ref_mft_entry;
      mft->filename[record_num] = UTF16toUTF8((char16_t*)(content+sizeof(ATTR_FILE_NAME)-sizeof(char16_t*)), fname_len);
      if(dump) {
        printf("    File Name: ");
        printFileName(record_num);
        printf("\n");
      }
      else {
        this->fname = getFileName(record_num);
      }
//      printUTF16((char16_t*)(content+sizeof(ATTR_FILE_NAME)-sizeof(char16_t*)), fname_len);

      break;


    case ATTRTYPEID_DATA:
      if(dump) {
        printf("\n  $DATA(%s)\n", (nonresident?"non-resident":"resident"));
      }

      if(!nonresident) { // resident
        if(dump) {
          printf("    File Size: %u\n", attr.header.resident.size);
        }
        if (attr.header.resident.size) {
          if((resdata = (RESIDENT_DATA*)malloc(sizeof(RESIDENT_DATA))) == NULL) {
#ifdef DEBUG
            perror("malloc");
            return -1;
#endif
          }
          resdata->name = NULL;
          resdata->len = attr.header.resident.size;
          if((resdata->data = (unsigned char*)malloc(resdata->len)) == NULL) {
#ifdef DEBUG
            perror("malloc");
            return -1;
#endif
          }
          for(int i = 0; i < attr.header.resident.size; i++) {
            *(resdata->data+i) = *((unsigned char*)content+(attr.header.resident.offset-header_size)+i);
          }
          if(attr.header.base.name_len) { // ADS
            resdata->name = (char*)UTF16toUTF8((char16_t*)((char*)(content-header_size)+attr.header.base.name_offset), attr.header.base.name_len).c_str();
          }
          this->resident_data.push_back(resdata);
        }
      }
      else {
        if(dump) {
          printf("    File Size: %llu\n", attr.header.nonresident.actual_attr_size);
        }
      }

      break;


    default:
#ifdef DEBUG
      fprintf(stderr, "\nAttribute ID %d is not implemented.\n", attrid);
#endif
      return 0;
  }
  return 0;
}


int FileRecord::VerifyFixup() {
  uint16_t *fixups;
  uint16_t fixup_value;
  uint16_t fixup_offset;
  uint16_t fixup_count;
  uint16_t offset;

  fixup_offset = this->record.fixup_offset;
  fixup_count = this->record.fixup_count;
  memcpy(&fixup_value, data+fixup_offset, sizeof(uint16_t));

  if(fixup_count) {
    fixups = (uint16_t*)malloc(sizeof(uint16_t)*fixup_count);
    memcpy(fixups, data+fixup_offset+sizeof(uint16_t), sizeof(uint16_t)*fixup_count);
    for(int i = 0; i < fixup_count-1; i++) {
      offset = this->mft->bytes_per_sector*(i+1)-2;

      if(memcmp(data+offset, &fixup_value, sizeof(uint16_t))) {
        fprintf(stderr, "fixup error at: %d\n", offset);
      }

      memcpy(data+offset, &fixups[i], sizeof(uint16_t));
    }
    free(fixups);
  }

  return 0;
}


void FileRecord::printFileName(uint64_t ref) {
  if(ref == 5) { // "." root
    printf("C:");
    return;
  }

  auto &filename = mft->filename;

  if(filename.find(ref) == filename.end()) {
    FileRecord fr(mft, mft->record_table[ref]);
    fr.ParseRecord(false);
  }

  printFileName(mft->ref_table[ref]);
  printf("\\%s", filename[ref].c_str());
}


string FileRecord::getFileName(uint64_t ref) {
  string res;
  if(ref == 5) { // "." root
    res = "C:";
    return res;
  }

  auto &filename = mft->filename;

  if(filename.find(ref) == filename.end()) {
    FileRecord fr(mft, mft->record_table[ref]);
    fr.ParseRecord(false);
  }

  // avoid self recursion
  if(ref == mft->ref_table[ref]) {
    return res;
  }

  res = getFileName(mft->ref_table[ref]);
  res += "\\" + filename[ref];
  return res;
}
