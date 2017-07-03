#include "utils.h"
#include "attribute.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctype.h>
#include <ctime>
#include <unistd.h>

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif

#define HEXDUMP_OUT stdout

void hexdump(void *mem, unsigned int len)
{
  unsigned int i, j;

  for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
  {
    /* print offset */
    if(i % HEXDUMP_COLS == 0)
    {
      fprintf(HEXDUMP_OUT, "0x%06x: ", i);
    }

    /* print hex data */
    if(i < len)
    {
      fprintf(HEXDUMP_OUT, "%02x ", 0xFF & ((char*)mem)[i]);
    }
    else /* end of block, just aligning for ASCII dump */
    {
      fprintf(HEXDUMP_OUT, "   ");
    }

    /* print ASCII dump */
    if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
    {
      for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
      {
        if(j >= len) /* end of block, not really printing */
        {
          putchar(' ');
        }
        else if(isprint(((char*)mem)[j])) /* printable char */
        {
          putchar(0xFF & ((char*)mem)[j]);        
        }
        else /* other char */
        {
          putchar('.');
        }
      }
      putchar('\n');
    }
  }
}


void parse_time(uint64_t _time, bool lt) {
  /*
     11644473600.0 seconds from 1601/01/01 to 1970/01/01
     */

  time_t epoch = _time/(10*1000*1000) - 11644473600L;
  int miliseconds = (_time%(10*1000*1000))/(1000*10);
  struct tm *tm_info;

  if(lt)
      tm_info = localtime(&epoch);
  else
      tm_info = gmtime(&epoch);

  char buf[32];
  strftime(buf, 26, "\"%Y/%m/%d %H:%M:%S", tm_info);
  printf(buf);
  printf(".%03d\"", miliseconds);
}


void parse_flags(uint64_t flags) {
/*
#define READ_ONLY     0x0001
#define HIDDEN        0x0002
#define SYSTEM        0x0004
#define ARCHIVE       0x0020
#define DEVICE        0x0040
#define NORMAL        0x0080
#define TEMPORARY     0x0100
#define SPARSE_FILE   0x0200
#define REPARSE_POINT 0x0400
#define COMPRESSED    0x0800
#define OFFLINE       0x1000
#define NOT_INDEXED   0x2000
#define ENCRYPTED     0x4000
*/

  printf("flags:");

  if(flags & READ_ONLY) 
    printf(" READ_ONLY");
  if(flags & HIDDEN) 
    printf(" HIDDEN");
  if(flags & SYSTEM)
    printf(" SYSTEM");
  if(flags & ARCHIVE)
    printf(" ARCHIVE");
  if(flags & DEVICE)
    printf(" DEVICE");
  if(flags & NORMAL)
    printf(" NORMAL");
  if(flags & TEMPORARY)
    printf(" TEMPORARY");
  if(flags & SPARSE_FILE)
    printf(" SPARSE_FILE");
  if(flags & REPARSE_POINT)
    printf(" REPARSE_POINT");
  if(flags & COMPRESSED)
    printf(" COMPRESSED");
  if(flags & OFFLINE)
    printf(" OFFLINE");
  if(flags & NOT_INDEXED)
    printf(" NOT_INDEXED");
  if(flags & ENCRYPTED)
    printf(" ENCRYPTED");

  printf("\n");
}


string UTF16toUTF8(char16_t *s, int n) {
  int half = 0;
  char *out = (char*)malloc(6);
  string res;

  // cite from:: ntfs-3g:unistr.c
  for (int i = 0; i < n; ++i) {
    uint16_t c = s[i];
    char *t = out;
    memset(t, 0, 6);
    if (half) {
      if ((c >= 0xdc00) && (c < 0xe000)) {
        *t++ = 0xf0 + (((half + 64) >> 8) & 7);
        *t++ = 0x80 + (((half + 64) >> 2) & 63);
        *t++ = 0x80 + ((c >> 6) & 15) + ((half & 3) << 4);
        *t++ = 0x80 + (c & 63);
        half = 0;
      }
    } else if (c < 0x80) {
      *t++ = c;
    } else {
      if (c < 0x800) {
        *t++ = (0xc0 | ((c >> 6) & 0x3f));
        *t++ = 0x80 | (c & 0x3f);
      } else if (c < 0xd800) {
        *t++ = 0xe0 | (c >> 12);
        *t++ = 0x80 | ((c >> 6) & 0x3f);
        *t++ = 0x80 | (c & 0x3f);
      } else if (c < 0xdc00)
        half = c;
      else if (c >= 0xe000) {
        *t++ = 0xe0 | (c >> 12);
        *t++ = 0x80 | ((c >> 6) & 0x3f);
        *t++ = 0x80 | (c & 0x3f);
      }
    }
    res += string(out);
  }

  free(out);

  return res;
}


void printUTF16(char16_t *s, int n) { // UTF16LE
  int half = 0;
  char *out = (char*)malloc(6);

  // cite from:: ntfs-3g:unistr.c
  for (int i = 0; i < n; ++i) {
    uint16_t c = s[i];
    char *t = out;
    memset(t, 0, 6);
    if (half) {
      if ((c >= 0xdc00) && (c < 0xe000)) {
        *t++ = 0xf0 + (((half + 64) >> 8) & 7);
        *t++ = 0x80 + (((half + 64) >> 2) & 63);
        *t++ = 0x80 + ((c >> 6) & 15) + ((half & 3) << 4);
        *t++ = 0x80 + (c & 63);
        half = 0;
      }
    } else if (c < 0x80) {
      *t++ = c;
    } else {
      if (c < 0x800) {
        *t++ = (0xc0 | ((c >> 6) & 0x3f));
        *t++ = 0x80 | (c & 0x3f);
      } else if (c < 0xd800) {
        *t++ = 0xe0 | (c >> 12);
        *t++ = 0x80 | ((c >> 6) & 0x3f);
        *t++ = 0x80 | (c & 0x3f);
      } else if (c < 0xdc00)
        half = c;
      else if (c >= 0xe000) {
        *t++ = 0xe0 | (c >> 12);
        *t++ = 0x80 | ((c >> 6) & 0x3f);
        *t++ = 0x80 | (c & 0x3f);
      }
    }
    printf("%s", out);
  }

  free(out);

  return;
}


string convUTF16(char16_t *s, int n) { // UTF16LE
  string res;
  int half = 0;
  char *out = (char*)malloc(6);

  // cite from:: ntfs-3g:unistr.c
  for (int i = 0; i < n; ++i) {
    uint16_t c = s[i];
    char *t = out;
    memset(t, 0, 6);
    if (half) {
      if ((c >= 0xdc00) && (c < 0xe000)) {
        *t++ = 0xf0 + (((half + 64) >> 8) & 7);
        *t++ = 0x80 + (((half + 64) >> 2) & 63);
        *t++ = 0x80 + ((c >> 6) & 15) + ((half & 3) << 4);
        *t++ = 0x80 + (c & 63);
        half = 0;
      }
    } else if (c < 0x80) {
      *t++ = c;
    } else {
      if (c < 0x800) {
        *t++ = (0xc0 | ((c >> 6) & 0x3f));
        *t++ = 0x80 | (c & 0x3f);
      } else if (c < 0xd800) {
        *t++ = 0xe0 | (c >> 12);
        *t++ = 0x80 | ((c >> 6) & 0x3f);
        *t++ = 0x80 | (c & 0x3f);
      } else if (c < 0xdc00)
        half = c;
      else if (c >= 0xe000) {
        *t++ = 0xe0 | (c >> 12);
        *t++ = 0x80 | ((c >> 6) & 0x3f);
        *t++ = 0x80 | (c & 0x3f);
      }
    }
    res += string(out);
  }

  free(out);

  return res;
}

void escapeDoubleQuote (std::string& str) {
  std::string::size_type pos = 0;
  while(pos = str.find("\"", pos), pos != std::string::npos) {
    str.replace(pos, 1, "\"\"");
    pos += 2;
  }
}
