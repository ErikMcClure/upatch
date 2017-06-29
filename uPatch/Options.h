// Copyright ©2017 Black Sphere Studios

#ifndef __OPTIONS_H__UPATCH__
#define __OPTIONS_H__UPATCH__

#include "uPatch.h"
#include "Payload.h"
#include "bss-util/UBJSON.h"
#include "bss-util/Logger.h"

#define UPLOG(level,...) (Options::log.Log(0,__FILE__,__LINE__,(level),__VA_ARGS__))
#define UPLOGFORMAT(level,format,...) (Options::log.LogFormat(0,__FILE__,__LINE__,(level),(format),__VA_ARGS__))

struct Options
{
  Options() {}
  Options(const char* file);
  void OverrideOptions(const char* const* p, size_t n);
  void Save(const char* file);

  bssVersionInfo curversion; // major, minor, revision
  std::vector<bss::Str> selfmirrors;
  std::vector<bss::Str> mirrors;
  std::vector<bss::Str> downloads;
  bss::Str selfdownload;
  bss::Str regroot;
  std::vector<bss::Str> trackfiles;
  std::vector<upatch::RegistryPayloadRemove> trackreg;
  int maxconcurrent;

  static const char* TEMP_EXE_PATH;
  static const wchar_t* TEMP_EXE_PATH_W;
  static const char* TEMP_HOP_PATH;
  static const char* CONFIG_PATH;
  static const char* SELF_UPDATE_PATH;
  static const char* SELF_CONTROL_FILE;
  static const char* DELTA_TEMP_NAME;
  static const char* DELTA_EXT_NAME;
  static bss::Logger log;

  template<typename Engine>
  void Serialize(bss::Serializer<Engine>& engine)
  {
    engine.template EvaluateType<Source>(
      GenPair("curversion", curversion.v),
      GenPair("selfmirrors", selfmirrors),
      GenPair("mirrors", mirrors),
      GenPair("downloads", downloads),
      GenPair("selfdownload", selfdownload),
      GenPair("regroot", regroot),
      GenPair("trackfiles", trackfiles),
      GenPair("trackreg", trackreg),
      GenPair("maxconcurrent", maxconcurrent)
      );
  }
};

#endif