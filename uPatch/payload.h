// Copyright ©2017 Black Sphere Studios

#ifndef __PAYLOAD_H__UPATCH__
#define __PAYLOAD_H__UPATCH__

#include "uPatch.h"
#include "bss-util\UBJSON.h"

namespace upatch {
  enum PATCH_TECH
  {
    PATCH_DEFAULT = 0,
    PATCH_NONE,
    PATCH_ZDELTA,
    PATCH_BSDIFF,
  };

  enum WIN32_ROOTKEY
  {
    ROOTKEY_DEFAULT = 0,
    ROOTKEY_CLASSES_ROOT,
    ROOTKEY_CURRENT_USER,
    ROOTKEY_LOCAL_MACHINE,
    ROOTKEY_USERS,
    ROOTKEY_PERFORMANCE_DATA,
    ROOTKEY_PERFORMANCE_TEXT,
    ROOTKEY_PERFORMANCE_NLSTEXT,
    ROOTKEY_CURRENT_CONFIG,
    ROOTKEY_DYN_DATA,
    ROOTKEY_CURRENT_USER_LOCAL_SETTINGS
  };

  // Remove fails if MD5 doesn't match, unless the update is forced
  struct BinaryPayloadRemove 
  {
    bss::Str path;
    MD5HASH target;
    bool absolute;

    template<typename Engine>
    void Serialize(bss::Serializer<Engine>& engine)
    {
      engine.template EvaluateType<BinaryPayloadRemove>(
        GenPair("p", path),
        GenPair("t", target)
        );
    }
  };

  // Add fails if the file already exists, unless the update is forced, in which case it overwrites it.
  struct BinaryPayloadAdd
  {
    bss::Str path;
    MD5HASH self;
    size_t data; // Stores the length of the data that was appended to the data chunk at the end of the payload
    bool absolute;

    template<typename Engine>
    void Serialize(bss::Serializer<Engine>& engine)
    {
      engine.template EvaluateType<BinaryPayloadAdd>(
        GenPair("p", path),
        GenPair("s", self),
        GenPair("l", data)
        );
    }
  };

  // Delta always fails if any MD5 check fails, even if forced.
  struct BinaryPayloadDelta
  {
    BinaryPayloadAdd file;
    MD5HASH target;
    MD5HASH result;
    PATCH_TECH patch;

    template<typename Engine>
    void Serialize(bss::Serializer<Engine>& engine)
    {
      engine.template EvaluateType<BinaryPayloadDelta>(
        GenPair("f", file),
        GenPair("t", target),
        GenPair("r", result)
        );
    }
  };

  // Registry remove attempts a remove, but won't raise an error if the entry isn't there.
  struct RegistryPayloadRemove
  {
    WIN32_ROOTKEY root;
    bss::Str path;
    bss::Str name;
    char type; // REG_DWORD, REG_SZ, REG_QWORD, REG_BINARY, etc. Use -1 if there is no data

    template<typename Engine>
    void Serialize(bss::Serializer<Engine>& engine)
    {
      engine.template EvaluateType<RegistryPayloadRemove>(
        GenPair("p", path),
        GenPair("t", type)
        );
    }
  };

  struct RegistryPayloadAdd // A registry add will simply overwrite any value there no matter what.
  {
    RegistryPayloadRemove entry;
    bss::Str sdata;
    uint64_t idata;

    template<typename Engine>
    void Serialize(bss::Serializer<Engine>& engine)
    {
      engine.template EvaluateType<RegistryPayloadAdd>(
        GenPair("e", entry),
        GenPair("s", sdata),
        GenPair("i", idata)
        );
    }
  };

  // Optional values to add to add/remove installation entry.
  struct InstallPayload
  {
    bss::Str displayname; // Name of the application
    bss::Str publisher;
    bss::Str helplink;
    bss::Str updateinfourl;
    bss::Str aboutinfourl;
    bss::Str mainexe; // path to the EXE to use for the display icon
    bss::Str comment;

    template<typename Engine>
    void Serialize(bss::Serializer<Engine>& engine)
    {
      engine.template EvaluateType<InstallPayload>(
        GenPair("displayname", displayname),
        GenPair("publisher", publisher),
        GenPair("helplink", helplink),
        GenPair("updateinfourl", updateinfourl),
        GenPair("aboutinfourl", aboutinfourl),
        GenPair("mainexe", mainexe),
        GenPair("comment", comment)
        );
    }

    bss::Str& operator[](size_t i)
    {
      switch(i)
      {
      case 0: return displayname;
      case 1: return publisher;
      case 2: return helplink;
      case 3: return updateinfourl;
      case 4: return aboutinfourl;
      case 5: return mainexe;
      }
      return comment;
    }
  };

  // Used when verifying payloads to mark a payload that was already applied by a previous update attempt, and should be skipped.
  struct SkipPayload { size_t data; template<typename E> void Serialize(bss::Serializer<E>&) {} };

  typedef bss::Variant<BinaryPayloadRemove, BinaryPayloadAdd, BinaryPayloadDelta, RegistryPayloadRemove, RegistryPayloadAdd, SkipPayload> PayloadPack;

  struct Payload
  {
    std::vector<PayloadPack> update;
    std::vector<PayloadPack> install;
    InstallPayload details;
    bssVersionInfo target; // This is the version you will have been updated to after applying this
    bssVersionInfo from; // This is the version you were upgrading from (if zero, this is not a delta pack)
    bool admin; // run update as admin (installs are always run as admin)

    template<typename Engine>
    void Serialize(bss::Serializer<Engine>& engine)
    {
      engine.template EvaluateType<Payload>(
        GenPair("u", update),
        GenPair("i", install),
        GenPair("a", admin)
        );
    }
  };
}

#endif