#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <getopt.h>

#include <iostream>
#include <fstream>

#include "mft.h"
#include "attribute.h"
#include "utils.h"

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
	printf("Usage: mft.exe [-o output] [--utc] [-e|--export] input\n");
}

void dump(char *inname) {
  MFT mft = MFT(inname);

  for(uint32_t record_num:mft.record_nums) {
      FileRecord *fr;
      if(mft.parse(record_num, fr)) {
        fprintf(stderr, "error\n");
        break;
      }
  }
}

std::string extractcomputername(char *inname) {
  std::string fullpath, folderpath, foldername;
  string ntfs = "\\NTFS";
  fullpath = inname;
  std::string::size_type pos;

  // trail filename
  if((pos = fullpath.find_last_of(SEP)) == string::npos)
    return ".";
  folderpath = fullpath.substr(0, pos);
  // trail NTFS folder
  if(folderpath.length() <= ntfs.length() || (pos = folderpath.find(ntfs, folderpath.length() - ntfs.length())) == std::string::npos)
    return ".";
  folderpath = folderpath.substr(0, pos);
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

void dumpcsv(char *inname) {
  MFT mft = MFT(inname);

  computername = extractcomputername(inname);
  
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
    printf("\"Security\"");
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

char* supplyinput(char *inname) {
  std::string inputname;
  std::string::size_type pos;  

  inputname = inname;
  
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
    
  char *inname = NULL;
  char *outname = NULL;
  const char *outdir;
  string infilename, inntfsname, infullname, outfullname;

  bool dumpresident = false; // dump resident data

  FILE* fp_out;
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
        outname = optarg;
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
    inname = argv[i];

  if (!inname) {
    usage();
    exit(EXIT_FAILURE);
  }

  // input handling
  if(isDir(inname)) {
	infilename = findFile(inname, "$MFT");
	if (infilename == "") {
		if (inname[string(inname).size()-1] == '\\')
			inntfsname = string(inname) + "NTFS";
		else
			inntfsname = string(inname) + SEP + "NTFS";
		const char* inntfs = inntfsname.c_str();		
		infilename = findFile(inntfs, "$MFT");
		if (infilename == "") {
			fprintf(stderr, "input file not found\n");
			return -1;
		}
		infullname = inntfsname + SEP + infilename;
	} else {
		if (inname[string(inname).size()-1] == '\\')
			infullname = string(inname) + infilename;
		else
			infullname = string(inname) + SEP + infilename;
	}
  } else if (isFile(inname)){
 	infullname = string(inname);
	std::string::size_type pos = infullname.find_last_of(SEP);  
	infilename = infullname.substr(pos+1, infullname.length()-pos);
  } else {
	fprintf(stderr, "error: no input\n");	
	exit(EXIT_FAILURE);
  }
  fprintf(stdout, "input: %s\n", infullname.c_str());

  // output handling
  if(outname != NULL) {
	if(isDir(outname)) {
	  outfullname = string(outname) + SEP + infilename + "_output.csv";
      outdir = outname;
	}
    else {
	  outfullname = string(outname);
	  std::string::size_type pos = outfullname.find_last_of(SEP);
      outdir = outfullname.substr(0, pos-1).c_str();	
	}
    fprintf(stdout, "output: %s\n", outfullname.c_str());
    fp_out = freopen(outfullname.c_str(),"a",stdout);
  }	else
	fprintf(stdout, "output: stdout\n");  

  char* infullname_cstr = new char[infullname.size() + 1];
  std::char_traits<char>::copy(infullname_cstr, infullname.c_str(), infullname.size() + 1);


  if(dumpresident) { // output resident data
    MFT mft = MFT(infullname_cstr);

    if(outname == NULL) {
      fprintf(stderr, "current version doesn't support dump option and stdout\n");  
      return -1;
    }

    string cmd = "mkdir "+string(outdir)+SEP+"mft";
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
          ofstream ofs(string(outdir)+SEP+"mft"+SEP+outfile);
          ofs << resi->data;
          ofs.close();
        }
        else { // ADS
          ofstream ofs(string(outdir)+SEP+"mft"+SEP+outfile+"_"+string(resi->name));
          ofs << resi->data;
          ofs.close();
        }
      }
      delete(fr);
    }

    return 0;
  }

//  inputname = supplyinput(inname);
  
  // calc time zone
  if(lt) {
    time_t t1, t2;
    time(&t1); // LocalTime UNIX epoch
    struct tm *tm_info;
	int diff_sec;

    tm_info = gmtime(&t1);
	t2 = mktime(tm_info); // UTC UNIX epoch
	diff_sec = t1-t2;
	tz_hour = diff_sec/3600;
	tz_min = (diff_sec/60) % 60;
	if(diff_sec >= 0)
      sprintf(tzstr, "+%02d:%02d", tz_hour, tz_min);
    else // -hh:mm
      sprintf(tzstr, "%03d:%02d", tz_hour, -tz_min);

  }
   
  dumpcsv(infullname_cstr);
  return 0;
}
