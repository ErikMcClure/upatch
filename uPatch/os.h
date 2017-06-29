// Copyright ©2017 Black Sphere Studios

#ifndef __OS_H__UPATCH__
#define __OS_H__UPATCH__

#include "Payload.h"

struct _GUID;

namespace upatch {
  bool DeleteSelf();
  bool ExecuteProcess(const char* str);
  bss::Str GetCurrentPath();
  unsigned long GetCurrentPID();
  void UninstallSelf(const char* file);
  bool UninstallRegistryEntry(const RegistryPayloadRemove& entry);
  bool InstallRegistryEntry(const RegistryPayloadAdd& entry);
  bool HasAdmin();
  void RestartWithAdmin(int argc, char** argv);
  void RestartWithAdmin(const char* arguments);
  bool CopyFiles(const char* src, const char* dest, bool overwrite = true);
  bss::Str GetGUID();
}

#endif