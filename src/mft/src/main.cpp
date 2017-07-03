#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <getopt.h>

#include <iostream>
#include <fstream>

#include "mft.h"
#include "attribute.h"

using namespace std;

#ifdef _WIN32
char SEP = '\\';
#else // unix
char SEP = '/';
#endif


// global variables
bool lt = true; // localtime
char tzstr[16]; // time zone
bool header = true; // output header
int tz_hour, tz_min; // time zone info
string computername; // extract from input full path
  
void usage(void) {
	printf("Usage: mft.exe -o output [--utc] [-e|--export] input\n");
}

void dump(char *fname) {
  MFT mft = MFT(fname);

  for(uint32_t record_num:mft.record_nums) {
      FileRecord *fr;
      if(mft.parse(record_num, fr)) {
        fprintf(stderr, "error\n");
        break;
      }
  }
}

std::string extractcomputername(char *fname) {
  std::string fullpath, folderpath, foldername;
  fullpath = fname;
  std::string::size_type pos;
  // trail filename
  if((pos = fullpath.find_last_of(SEP)) == string::npos)
    return ".";
  folderpath = fullpath.substr(0, pos);
  // extract foldername
  if((pos = folderpath.find_last_of(SEP)) == string::npos)
    return ".";
  foldername = folderpath.substr(pos+1, folderpath.length()-(pos+1));
  // extract computername
  pos = foldername.find_last_of('_');
  if (pos == std::string::npos) {
    return ".";
  }
  return foldername.substr(0, pos);
}

void dumpcsv(char *fname) {
  MFT mft = MFT(fname);

  computername = extractcomputername(fname);
  
  if(header==true) {
    // output CSV headers
    printf("\"ComputerName\"");
    printf("\t");
    printf("\"Filename\"");
    printf("\t");
    printf("\"Path\"");
    printf("\t");
    printf("\"FileID\"");
    printf("\t");
    printf("\"Flag\"");
    printf("\t");
    printf("\"FileSize\"");
    printf("\t");
    printf("\"Created\"");
    printf("\t");
    printf("\"Modified\"");
    printf("\t");
    printf("\"RecordChanged\"");
    printf("\t");
    printf("\"Accessed\"");
    printf("\t");
    printf("\"Created($FN)\"");
    printf("\t");
    printf("\"Modified($FN)\"");
    printf("\t");
    printf("\"RecordChanged($FN)\"");
    printf("\t");
    printf("\"Accessed($FN)\"");
    printf("\t");
    printf("\"TimeZone\"");
    printf("\t");
    printf("\"Owner\"");
    printf("\t");
    printf("\"Misc\"");
    printf("\n");
  }

  for(uint32_t record_num:mft.record_nums) {
    FileRecord *fr;
    if(mft.parse_csv(record_num, fr)) {
      fprintf(stderr, "error: record_num %d\n", record_num);
      break;
    }
  }
}

char* supplyinput(char *fname) {
  std::string inputname;
  std::string::size_type pos;  

  inputname = fname;
  
  if(inputname[inputname.length()-1] == SEP)
    inputname += "$MFT";
  else {
    pos = inputname.find_last_of(SEP); 
    if(inputname.substr(pos+1, inputname.length()-(pos+1)) != "$MFT") {
      inputname += SEP;
      inputname += "$MFT";
    }
  }
  

  char* inputname_cstr = new char[inputname.size() + 1];
  std::char_traits<char>::copy(inputname_cstr, inputname.c_str(), inputname.size() + 1);  
  return inputname_cstr;
}

int main(int argc, char **argv) {
    
  char *fname = NULL;
  char *dirname = NULL;
  char *inputname;
  bool dumpresident = false; // dump resident data

  int opt;
  int longindex;
  
  struct option longopts[] = {
    {"help", no_argument, NULL, 'h'},
    {"output", required_argument, NULL, 'o'},
    {"noheader", no_argument, NULL, 30}, 
    {"utc", no_argument, NULL, 31}, 
    {"export", no_argument, NULL, 'e'}, 
    {0, 0, 0, 0},
  };

  while((opt = getopt_long(argc, argv, "o:h:e", longopts, &longindex)) != -1) {
    switch(opt) {
     
      case 'o':
        dirname = optarg;
        break;

      case 'h':
        usage();
        exit(EXIT_FAILURE);

      case 30:
        header=false;
        break;

      case 31:
        lt=false;
        break;
 
      case 'e':
        dumpresident = true;
        break;
   }
  }
  for (int i = optind; i < argc; i++)
    fname = argv[i];

  if (!fname) {
    usage();
    exit(EXIT_FAILURE);
  }

  if(dumpresident) { // output resident data
    MFT mft = MFT(fname);

    if(dirname == NULL) {
      usage();
      return -1;
    }

    string cmd = "mkdir "+string(dirname)+SEP+"mft";
    if(system(cmd.c_str())) {
      fprintf(stderr, "failed to create directory\n");
      return -1;
    }

    for(uint32_t record_num:mft.record_nums) {
      FileRecord *fr = new FileRecord(&mft, mft.record_table[record_num]);
      if(mft.parse(record_num, fr, false)) {
        fprintf(stderr, "mft record parse error (%u)\n", record_num);
        break;
      }
      string outfile = fr->fname;
      string::size_type pos;
      while((pos = outfile.find_first_of('\\')) != string::npos) { // replace all '\\' to '_'
        outfile = outfile.replace(pos, 1, "_");
      }
      while((pos = outfile.find_first_of(':')) != string::npos) { // replace all ':' to '_'
        outfile = outfile.replace(pos, 1, "_");
      }

      for(auto resi:fr->resident_data) {
        if(resi->name == NULL) { // file name
          ofstream ofs(string(dirname)+SEP+"mft"+SEP+outfile);
          ofs << resi->data;
          ofs.close();
        }
        else { // ADS
          ofstream ofs(string(dirname)+SEP+"mft"+SEP+outfile+"_"+string(resi->name));
          ofs << resi->data;
          ofs.close();
        }
      }
      delete(fr);
    }

    return 0;
  }

  inputname = supplyinput(fname);
  
  if (dirname != NULL) {
    std::string oname = "mft_output.csv";
    std::string opathname = string(dirname) + SEP + oname;
    FILE* fp_out = freopen(opathname.c_str(),"a",stdout);
  }

  // calc time zone
  if(lt) {
    time_t t1, t2;
    time(&t1);
    struct tm *tm_info;

    tm_info = localtime(&t1);
    tz_hour = tm_info->tm_hour;
    tz_min = tm_info->tm_min;	

    tm_info = gmtime(&t1);
    tz_hour -= tm_info->tm_hour;
    tz_min -= tm_info->tm_min;
	t2 = mktime(tm_info);
	
	if(t1-t2 > 0 && tz_hour < 0)
		tz_hour += 24;

    if(tz_min < 0) {
      tz_min += 60;
      tz_hour--;
    }

	
    if(tz_hour >= 0) {
      sprintf(tzstr, "+%02d:%02d", tz_hour, tz_min);
    }
    else {
      sprintf(tzstr, "%02d:%02d", tz_hour, tz_min);
    }
  }
   
  dumpcsv(inputname);
  return 0;
}
