// Copyright ©2017 Black Sphere Studios

#include "Options.h"
#include "bss-util/JSON.h"
#include <fstream>

using namespace bss;

const char* Options::TEMP_EXE_PATH = "~upatch.exe";
const wchar_t* Options::TEMP_EXE_PATH_W = L"~upatch.exe";
const char* Options::TEMP_HOP_PATH = "~patch-%hu_%hu_%hu_%hu-%hu_%hu_%hu_%hu.dlcache";
const char* Options::CONFIG_PATH = "uPatch.cfg";
const char* Options::SELF_UPDATE_PATH = "~selfupdate.dlcache";
const char* Options::SELF_CONTROL_FILE = "upatch.control.json";
const char* Options::DELTA_TEMP_NAME = "~delta.dlcache";
const char* Options::DELTA_EXT_NAME = ".delta.tmp";
bss::Logger Options::log;

Options::Options(const char* file)
{
  std::ifstream fs(file, std::ios_base::in | std::ios_base::binary);
  if(fs)
  {
    ParseJSON<Options>(*this, fs);
    fs.close();
  }
}
void Options::OverrideOptions(const char* const* p, size_t n)
{
  static const Trie<short> OptTrie(8, "version", "selfmirrors", "targetmirrors", "downloads", "selfdownload", "trackfiles", "trackreg", "maxconcurrent");

  switch(OptTrie[p[1]])
  {
  case 0:
  {
    int c = 0;
    for(Str& i : Str::Explode('.', p[2]))
    {
      curversion.v[3 - c++] = atoi(i);
      if(c > 3) break;
    }
    break;
  }
  case 1: selfmirrors.push_back(p[2]); break;
  case 2: mirrors.push_back(p[2]); break;
  case 3:
    for(uint32_t i = 1; i < n; ++i)
      downloads.push_back(p[i]);
    break;
  case 4: selfdownload = p[2];
  case 5:
    for(uint32_t i = 1; i < n; ++i)
      trackfiles.push_back(p[i]);
    break;
  case 7: maxconcurrent = atoi(p[2]); break;
  }
}

void Options::Save(const char* file)
{
  std::fstream fs(file, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
  WriteJSON<Options>(*this, fs, 1);
  fs.close();
}