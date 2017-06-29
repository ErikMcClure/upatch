// Copyright ©2017 Black Sphere Studios

#ifndef __SOURCE_H__UPATCH__
#define __SOURCE_H__UPATCH__

#include "uPatch.h"
#include "bss-util/Str.h"
#include "bss-util/Serializer.h"

struct Source
{
  struct Hop
  {
    bssVersionInfo from; // Zero'd if not used, which means this isn't a delta and is instead a full installation
    bssVersionInfo to;
    bss::Str md5;
    std::vector<bss::Str> mirrors;

    template<typename Engine>
    void Serialize(bss::Serializer<Engine>& engine)
    {
      engine.template EvaluateType<Hop>(
        GenPair("from", from.v),
        GenPair("to", to.v),
        GenPair("md5", md5),
        GenPair("mirrors", mirrors)
        );
    }

    static Hop EMPTY;
  };

  bssVersionInfo latest;
  std::vector<Hop> hops;

  template<typename Engine>
  void Serialize(bss::Serializer<Engine>& engine)
  {
    engine.template EvaluateType<Source>(
      GenPair("latest", latest.v),
      GenPair("hops", hops)
      );
  }

  static ERROR_CODES Load(Source& src, const char* url, const char* file);
};

#endif