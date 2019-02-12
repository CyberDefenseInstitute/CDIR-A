#include "filerecord.h"
#include "utils.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <iostream>

using namespace std;


int FileRecord::ParseRecord_csv(void) {
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

  csvrecord.fileid = this->record.record_num;

  VerifyFixup();
  ParseAttrs_csv(data+(this->record.fattr_offset));
  csvrecord.flag = this->record.flags;

  // output CSV
  // ComputerName
  escapeDoubleQuote(computername);
  printf("\"%s\"", computername.c_str());
  printf("\t"); 
  
  // Filename
  escapeDoubleQuote(csvrecord.filename);
  printf("\"%s\"", csvrecord.filename.c_str());
  printf("\t"); 
  // Pathname
  escapeDoubleQuote(csvrecord.pathname);
  printf("\"%s\"", csvrecord.pathname.c_str());
  printf("\t"); 

  // FileID
  printf("\"%lu\"", csvrecord.fileid);
  printf("\t"); 

  // Flag (2bit: isdirectory, 1bit: in use)
  printf((csvrecord.flag&0x2)?"\"Directory":"\"File");
  printf((csvrecord.flag&0x1)?"\"":"(Deleted)\"");
  printf("\t");

  // FileSize
  printf("\"%lu\"", csvrecord.filesize);
  printf("\t");

  // TimeStamp
  parse_time(csvrecord.created, lt);
  printf("\t");
  parse_time(csvrecord.modified, lt);
  printf("\t");
  parse_time(csvrecord.recordchanged, lt);
  printf("\t");
  parse_time(csvrecord.accessed, lt);
  printf("\t");

  // TimeStamp ($FILE_NAME)
  parse_time(csvrecord.created_fn, lt);
  printf("\t");
  parse_time(csvrecord.modified_fn, lt);
  printf("\t");
  parse_time(csvrecord.recordchanged_fn, lt);
  printf("\t");
  parse_time(csvrecord.accessed_fn, lt);
  printf("\t");

  // TimeZone (always UTC+0)
  if(lt)
    printf("\"%s\"\t", tzstr);
  else
    printf("\"UTC\"\t");
  
  printf("\"%u\"", csvrecord.owner);
  printf("\t");
  printf("\"%u\"", csvrecord.security);
  printf("\t");

  // Misc
  escapeDoubleQuote(csvrecord.misc);
  printf("\"%s\"", csvrecord.misc.c_str());
  printf("\n");

  free(data);

  return 0;
}


int FileRecord::ParseAttrs_csv(unsigned char *p) {
  // base
  unsigned char *tmp;
  uint32_t attrid;
  uint32_t header_size;
  ATTR attr;

  // FILE_NAME
  char16_t *fname;
  uint8_t fname_len;

  // To clean filesize parameter
  csvrecord.filesize = 0;

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
      if(!csvrecord.misc.empty()) {
        csvrecord.misc += ",";
      }
      csvrecord.misc += convUTF16((char16_t*)(tmp+(attr.header.base.name_offset)), attr.header.base.name_len);
    }

    ParseAttr_csv(attr, tmp+header_size);
  }

  return 0;
}


// parse each attribute (not including header)
int FileRecord::ParseAttr_csv(ATTR attr, unsigned char *content) {
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


  attrid = attr.header.base.attr_typeid;

  if(attr.header.base.flag_nonresident) {
    nonresident = true;
    header_size = sizeof(ATTR_HEADER_NONRESIDENT);
    content_size = attr.header.base.attr_len - sizeof(ATTR_HEADER_NONRESIDENT);
  }
  else {
    nonresident = false;
    header_size = sizeof(ATTR_HEADER_RESIDENT);
    content_size = attr.header.base.attr_len - sizeof(ATTR_HEADER_RESIDENT);
  }
  

  switch(attrid) {
    case ATTRTYPEID_STANDARD_INFORMATION:
      memcpy(&(attr.content), content, sizeof(ATTR_STANDARD_INFORMATION));
      csvrecord.created = attr.content.standard_information.creationtime;
      csvrecord.modified = attr.content.standard_information.file_altered_time;
      csvrecord.recordchanged = attr.content.standard_information.mft_altered_time;
      csvrecord.accessed = attr.content.standard_information.file_accessed_time;
	  csvrecord.owner = attr.content.standard_information.owner_id;
	  csvrecord.security = attr.content.standard_information.security_id;
      break;

    case ATTRTYPEID_ATTRIBUTE_LIST:
      for(unsigned char *c = content;
          c < content+content_size;
          c += attr.content.attribute_list.entry_len) {
            
        memcpy(&(attr.content), c, sizeof(ATTR_ATTRIBUTE_LIST));
        
        // avoid infinity loop
        if(attr.content.attribute_list.entry_len == 0)
          break;
        // TODO: validation for this process

        switch(attr.content.attribute_list.attr_type) {
          case ATTRTYPEID_FILE_NAME:
            ref = attr.content.attribute_list.attr_file_ref_record;
            fr = new FileRecord(mft, mft->record_table[ref]);
            if(!fr->ParseRecord(false)) {
              mft->ref_table[record_num] = mft->ref_table[ref];
              mft->filename[record_num] = mft->filename[ref];
            }
            delete(fr);
            break;
        }
      }
      break;
      

    case ATTRTYPEID_FILE_NAME:
      memcpy(&(attr.content), content, sizeof(ATTR_FILE_NAME));
      fname_len = attr.content.file_name.fname_len;

      // POSIX(0) > WIN32&DOS(3) > other
      if(  csvrecord.ns_tmp == -1
        || csvrecord.ns_tmp != 0 && attr.content.file_name.fname_space == 0
        || csvrecord.ns_tmp != 0 && attr.content.file_name.fname_space == 3
        || csvrecord.ns_tmp == 3 && attr.content.file_name.fname_space == 0) {

        csvrecord.created_fn = attr.content.file_name.creationtime;
        csvrecord.modified_fn = attr.content.file_name.file_altered_time;
        csvrecord.recordchanged_fn = attr.content.file_name.mft_altered_time;
        csvrecord.accessed_fn = attr.content.file_name.file_accessed_time;

        // update ns_tmp
        csvrecord.ns_tmp = attr.content.file_name.fname_space;
      }

      mft->ref_table[record_num] = attr.content.file_name.parent_ref_mft_entry;
      mft->filename[record_num] = UTF16toUTF8((char16_t*)(content+sizeof(ATTR_FILE_NAME)-sizeof(char16_t*)), fname_len);
      csvrecord.filename = mft->filename[record_num];
      csvrecord.pathname = getFileName(mft->ref_table[record_num]);
      break;


    case ATTRTYPEID_DATA:
      if(attr.header.base.name_len == 0) {
        csvrecord.filesize = nonresident ? 
            attr.header.nonresident.actual_attr_size : 
            attr.header.resident.size;
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
