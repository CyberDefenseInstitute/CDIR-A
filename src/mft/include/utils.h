#include <cstdint>
#include <string>

using namespace std;

void hexdump(void*, unsigned int);
void parse_time(uint64_t, bool);
string UTF16toUTF8(char16_t*, int);
void printUTF16(char16_t*, int);
string convUTF16(char16_t*, int);
void escapeDoubleQuote (std::string& str);
bool isDir(const char *);
bool isFile(const char *);
string findFile(const char*, const char*);
