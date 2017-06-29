// Copyright ©2017 Black Sphere Studios

#ifndef __UTIL_H__UPATCH__
#define __UTIL_H__UPATCH__

#include "Source.h"
#include "Payload.h"
#include <istream>
#include <ostream>

namespace upatch {
  struct InstallPayload;

  ERROR_CODES ToControlError(ERROR_CODES err);
  char PackZip(std::istream& in, std::ostream& out, char level);
  char UnpackZip(std::istream& in, std::ostream& out);
  ERROR_CODES DownloadFile(const char* url, std::ostream& s, uint8_t(&md5hash)[16], int(*callback)(void*, long long, long long, long long, long long), void* callbackdata);
  ERROR_CODES DownloadHop(const Source::Hop& hop, std::ostream& s, int(*callback)(void*, long long, long long, long long, long long), void* callbackdata);
  size_t CalcMD5(std::istream& in, uint8_t(&out)[16]); // Returns the total number of bytes read
  bss::Str ConvertMD5(const uint8_t(&in)[16]);
  bool ConvertMD5(const char* in, uint8_t(&out)[16]);
  bool CompareMD5(uint8_t(&l)[16], uint8_t(&r)[16], const char* debugname);
  bool CheckWritePermission(const char* file);
  void FindHops(bssVersionInfo version, const Source& src, std::vector<Source::Hop>& out);
  ERROR_CODES CreatePatch(const char* from, const char* to, const char* reg, Payload& payload, std::ostream& out);
  ERROR_CODES CreatePatchGit(const char* commitfrom, const char* curcommit, const char* reg, Payload& payload, std::ostream& out);
  ERROR_CODES ParseReg(std::istream& file, std::vector<PayloadPack>& pack);
  bss::Str GetCurrentDir();
  bss::Str GetCurrentName();
}

#endif
