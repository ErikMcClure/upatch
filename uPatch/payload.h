// Copyright ©2015 Black Sphere Studios

#ifndef __PAYLOAD_H__
#define __PAYLOAD_H__

#include "uPatch.h"
#include "bss-util\cUBJSON.h"

using namespace bss_util;

struct BinaryPayload
{
  cStr path;
  UBJSONValue::UBJSONBinary file;
  const char md5[16];
};

struct RegPayload
{
  cStr path;
  cStr sdata;
  uint64 idata;
  char type; // REG_DWORD, REG_SZ, REG_QWORD, REG_BINARY, etc. Use -1 if there is no data
};

// Optional values to add to add/remove installation entry. The installer will automatically
// populate UninstallString, QuietUninstallString, InstallLocation, InstallSource, 
// DisplayVersion, VersionMajor, VersionMinor, and EstimatedSize.
struct InstallPayload
{ 
  cStr displayname;
  cStr publisher;
  cStr regowner;
  cStr regcompany;
  cStr helplink;
  cStr updateinfourl;
  cStr aboutinfourl;
  cStr comment;
};

struct Payload
{
  PAYLOAD type;
  variant<BinaryPayload, RegPayload, InstallPayload> payload;
};

struct PayloadPack
{
  bool admin; // run update as admin (installs are always run as admin)
  std::vector<Payload> update;
  std::vector<Payload> install; // These list payloads that are specific to new installations only.
};

#endif