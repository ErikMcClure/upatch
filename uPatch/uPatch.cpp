// Copyright ©2017 Black Sphere Studios

#include "Payload.h"
#include "Util.h"
#include "Source.h"
#include "Options.h"
#include "os.h"
#include "Patches.h"
#include "bss-util/os.h"
#include "bss-util/stream.h"
#include "bss-util/JSON.h"
#include "curl/curl.h"
#include <iostream>
#include <fstream>

using namespace bss;
using namespace upatch;

bssVersionInfo uPatchVersion = { UPATCH_VERSION_REVISION, UPATCH_VERSION_MINOR, UPATCH_VERSION_MAJOR };

inline int CheckGenericUpdate(const std::vector<Str>& mirrors, uint64_t version, struct Source* out, ERROR_CODES returnerror)
{
  Source self;
  if(!out) // Out is optional, in case you are only checking for the existence of an update
    out = &self;

  ERROR_CODES err = ERR_NO_VALID_MIRRORS;
  for(auto& mirror : mirrors)
  {
    if((err = Source::Load(*out, mirror, 0)) == ERR_SUCCESS)
      break;
  }

  if(err != ERR_SUCCESS)
    return err;

  return (version >= out->latest.version) ? ERR_SUCCESS : returnerror;
}

int CheckSelfUpdate(const struct Options* options, struct Source* out)
{
  if(!options)
    return ERR_INVALID_ARGUMENTS;
  return CheckGenericUpdate(options->selfmirrors, uPatchVersion.version, out, ERR_SELF_UPDATE_AVAILABLE);
}

int DownloadSelfUpdate(struct Options* options, const Source* src, const char* file)
{
  if(!options)
    return ERR_INVALID_ARGUMENTS;

  Source self;
  int err = ERR_SUCCESS;
  if(!src)
  {
    src = &self;
    if((err = CheckSelfUpdate(options, &self)) < 0)
      return err;
  }

  if(uPatchVersion.version >= src->latest.version)
    return ERR_SUCCESS; // No update needed
  if(!file)
    file = Options::TEMP_EXE_PATH;
  
  // Calculate hops to us (should always be one because self-updates don't use deltas)
  std::vector<Source::Hop> hops;
  FindHops(uPatchVersion, *src, hops);
  if(!hops.size())
    return ERR_NO_UPDATE_PATH;

  std::ofstream fs(file, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
  if((err = DownloadHop(hops[0], fs, 0, 0)) != ERR_SUCCESS)
    return err;
  options->selfdownload = file;
  options->Save(Options::CONFIG_PATH);
  return ERR_SELF_UPDATE_DOWNLOADED;
}

int ApplySelfUpdate(struct Options* options, const char* file)
{
  if(!options)
    return ERR_INVALID_ARGUMENTS;

  if(file)
    options->selfdownload = file;
  else if(DownloadSelfUpdate(options, 0, Options::TEMP_EXE_PATH) == ERR_SUCCESS)
    return ERR_SUCCESS;

  if(!options->selfdownload.size() || !FileExists(options->selfdownload.c_str()))
    return ERR_DOWNLOAD_NOT_FOUND;

  Str target = options->selfdownload;
  options->selfdownload.clear(); // Save and wipe selfdownload to signal that it's been processed
  options->Save(Options::CONFIG_PATH);

  // Execute a new process that will wait until this one quits, then delete this EXE and move itself to where we are now.
  ExecuteProcess(StrF("\"%s\" -w %i -s \"%s\"", target.c_str(), GetCurrentPID(), GetCurrentPath()));

  return ERR_SELF_INSTALL_COMPLETE;
}

int CheckUpdate(const struct Options* options, struct Source* out)
{
  if(!options)
    return ERR_INVALID_ARGUMENTS;
  return CheckGenericUpdate(options->mirrors, options->curversion.version, out, ERR_UPDATE_AVAILABLE);
}

int DownloadUpdate(struct Options* options, const Source* src)
{
  if(!options)
    return ERR_INVALID_ARGUMENTS;

  Source self;
  int err = ERR_SUCCESS;
  if(!src)
  {
    src = &self;
    if((err = CheckUpdate(options, &self)) < 0)
      return err;
  }

  if(options->curversion.version >= src->latest.version)
    return ERR_SUCCESS; // No update needed

  // Calculate hops to us
  std::vector<Source::Hop> hops;
  FindHops(options->curversion, *src, hops);
  if(!hops.size())
    return ERR_NO_UPDATE_PATH;

  for(auto& hop : hops)
  {
    Str file = StrF(Options::TEMP_HOP_PATH, hop.from.Major, hop.from.Minor, hop.from.Revision, hop.from.Build, hop.to.Major, hop.to.Minor, hop.to.Revision, hop.to.Build);
    std::ofstream fs(file, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
    if((err = DownloadHop(hop, fs, 0, 0)) != ERR_SUCCESS)
    {
      options->Save(Options::CONFIG_PATH);
      return err;
    }
    options->downloads.push_back(file);
  }
  
  options->Save(Options::CONFIG_PATH);
  return ERR_SELF_UPDATE_DOWNLOADED;
}

ERROR_CODES VerifyPayload(PayloadPack& pack, const char* dir, bool force)
{
  Str path;
  MD5HASH hash;

  switch(pack.tag())
  {
  case PayloadPack::Type<BinaryPayloadAdd>::value:
    path = dir + pack.get<BinaryPayloadAdd>().path;

    if(FileExists(path)) // If the file exists, check to see if it's identical to us. If so, skip it.
    {
      std::fstream fs(path, std::ios_base::in | std::ios_base::binary);
      CalcMD5(fs, hash);
      if(CompareMD5(hash, pack.get<BinaryPayloadAdd>().self, 0))
      {
        pack = SkipPayload{ pack.get<BinaryPayloadAdd>().data };
        UPLOG(4, "Skipping ", path);
        return ERR_SUCCESS;
      }
      if(!force) // Otherwise return an error if we aren't forcing an overwrite
      {
        UPLOG(2, "File already exists, force overwrite required: ", path);
        return ERR_TARGET_MISMATCH;
      }
    }
    break;
  case PayloadPack::Type<BinaryPayloadRemove>::value:
    path = dir + pack.get<BinaryPayloadRemove>().path;

    if(!FileExists(path))
    {
      pack = SkipPayload{ 0 };
      UPLOG(4, "Skipping ", path);
      return ERR_SUCCESS;
    }
    else
    {
      std::fstream fs(path, std::ios_base::in | std::ios_base::binary);
      CalcMD5(fs, hash);
      if(!CompareMD5(hash, pack.get<BinaryPayloadRemove>().target, "Target") && !force)
        return ERR_TARGET_MISMATCH;
      if(!CheckWritePermission(path))
        return ERR_INSTALL_ACCESS_DENIED;
    }
    break;
  case PayloadPack::Type<BinaryPayloadDelta>::value:
    path = dir + pack.get<BinaryPayloadDelta>().file.path;

    if(!FileExists(path))
      return ERR_TARGET_MISMATCH;
    else
    {
      std::fstream fs(path, std::ios_base::in | std::ios_base::binary);
      CalcMD5(fs, hash);
      if(CompareMD5(hash, pack.get<BinaryPayloadDelta>().result, 0)) // If the target matches what we should end up with, we already applied this file, so skip it.
      {
        pack = SkipPayload{ pack.get<BinaryPayloadDelta>().file.data };
        UPLOG(4, "Skipping ", path);
        return ERR_SUCCESS;
      }
      if(!CompareMD5(hash, pack.get<BinaryPayloadDelta>().target, "Target file"))
      {
        return ERR_TARGET_MISMATCH;
      }
      if(!CheckWritePermission(path))
        return ERR_INSTALL_ACCESS_DENIED;
    }
    break;
  }

  return ERR_SUCCESS;
}

char CompBssStr(const Str& l, const Str& r) { return (char)STRICMP(l, r); }

ERROR_CODES ApplyPayload(struct Options* options, PayloadPack& pack, std::istream& data, const char* dir)
{
  Str path;
  switch(pack.tag())
  {
  case PayloadPack::Type<BinaryPayloadAdd>::value:
  {
    path = pack.get<BinaryPayloadAdd>().absolute ? pack.get<BinaryPayloadAdd>().path : dir + pack.get<BinaryPayloadAdd>().path;
    UPLOG(4, "Adding ", path);
    std::fstream fs(path, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
    fs << data.rdbuf();
    fs.close();
    fs.open(path, std::ios_base::in | std::ios_base::binary);
    MD5HASH hash;
    CalcMD5(fs, hash);
    fs.close();
    if(!CompareMD5(hash, pack.get<BinaryPayloadAdd>().self, "Installed file"))
    {
      std::remove(path);
      return ERR_TARGET_MISMATCH;
    }
    options->trackfiles.push_back(path);
  }
    break;
  case PayloadPack::Type<BinaryPayloadRemove>::value:
    path = pack.get<BinaryPayloadRemove>().absolute ? pack.get<BinaryPayloadRemove>().path : dir + pack.get<BinaryPayloadRemove>().path;
    UPLOG(4, "Deleting ", path);
    if(!std::remove(path))
      UPLOG(3, "Failed to remove file: ", path);

    {
      size_t i = bss::BinarySearchExact<Str, Str, size_t, CompBssStr>(options->trackfiles.data(), path, 0, options->trackfiles.size());
      if(i != (size_t)-1)
        options->trackfiles.erase(options->trackfiles.begin() + i);
    }
    break;
  case PayloadPack::Type<BinaryPayloadDelta>::value:
    {
      path = pack.get<BinaryPayloadDelta>().file.absolute ? pack.get<BinaryPayloadDelta>().file.path : dir + pack.get<BinaryPayloadDelta>().file.path;
      UPLOG(4, "Applying delta to ", path);
      MD5HASH hash;
      std::ifstream fsource(path, std::ios_base::in | std::ios_base::binary);
      std::ofstream fout(Options::DELTA_TEMP_NAME, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
      auto pos = data.tellg();
      ERROR_CODES err = DeltaApply(fsource, data, pack.get<BinaryPayloadDelta>().file.data, fout, pack.get<BinaryPayloadDelta>().patch);
      fsource.close();
      fout.close();
      assert(data.tellg() == pos + std::streamoff(pack.get<BinaryPayloadDelta>().file.data));
      if(err != ERR_SUCCESS)
      {
        UPLOG(2, "Error applying patch: ", err);
        std::remove(Options::DELTA_TEMP_NAME);
        return err;
      }

      std::fstream fs(Options::DELTA_TEMP_NAME, std::ios_base::in | std::ios_base::binary);
      CalcMD5(fs, hash);
      fs.close();
      if(!CompareMD5(hash, pack.get<BinaryPayloadDelta>().result, "Resulting file"))
      {
        std::remove(Options::DELTA_TEMP_NAME);
        return ERR_INSTALL_FAILED;
      }
      if(!std::remove(path))
      {
        return ERR_INSTALL_ACCESS_DENIED;
        UPLOG(2, "Failed to remove old file: ", path);
      }
      if(!std::rename(Options::DELTA_TEMP_NAME, path))
      {
        return ERR_INSTALL_ACCESS_DENIED;
        UPLOG(2, "Failed to rename new file: ", Options::DELTA_TEMP_NAME, " -> ", path);
      }
    }
    break;
  case PayloadPack::Type<RegistryPayloadAdd>::value:
    if(!InstallRegistryEntry(pack.get<RegistryPayloadAdd>()))
      ERR_FATAL;
    break;
  case PayloadPack::Type<RegistryPayloadRemove>::value:
    if(!UninstallRegistryEntry(pack.get<RegistryPayloadRemove>()))
      ERR_FATAL;
    break;
  case PayloadPack::Type<SkipPayload>::value:
    data.seekg(pack.get<SkipPayload>().data, std::ios_base::cur);
    break;
  }

  return ERR_SUCCESS;
}
ERROR_CODES ApplyHop(struct Options* options, std::istream& fs, const char* dir, bool install, bool force, bssVersionInfo& target, Payload& payload)
{
  Str curdir = GetCurrentDir();
  if(!dir)
    dir = curdir.c_str();

  assert(dir[strlen(dir) - 1] == '/' || dir[strlen(dir) - 1] == '\\');

  try
  {
    ParseUBJSON<Payload>(payload, fs);
  }
  catch(std::runtime_error e)
  {
    UPLOGFORMAT(2, "Payload parse error: ", e.what());
    return ERR_DOWNLOAD_CORRUPT;
  }
  UPLOGFORMAT(4, "Applying hop {0}.{1}.{2}.{3} -> {4}.{5}.{6}.{7}",
    payload.from.Major, payload.from.Minor, payload.from.Revision, payload.from.Build,
    payload.target.Major, payload.target.Minor, payload.target.Revision, payload.target.Build);

  if((payload.admin || install) && !HasAdmin())
  {
    RestartWithAdmin("-u");
    return ERR_REQUESTED_ADMIN_RIGHTS; // Because this is nonzero, it will be detected as an "error" and we'll immediately terminate
  }
  if(!payload.from.version || install)
    force = true;

  // First we verify that everything appears to be in order before attempting the update
  for(auto& pack : payload.update)
    if(ERROR_CODES err = VerifyPayload(pack, dir, force))
      return err;

  if(install)
  {
    for(auto& pack : payload.install)
      if(ERROR_CODES err = VerifyPayload(pack, dir, force))
        return err;
  }

  bool success = true;

  for(auto& pack : payload.update) // If we get an error at this stage, we cannot recover, so we ignore it and keep going, but don't increment the version number
    if(ApplyPayload(options, pack, fs, dir) != ERR_SUCCESS)
      success = false;

  if(install)
  {
    for(auto& pack : payload.install)
      if(ApplyPayload(options, pack, fs, dir) != ERROR_SUCCESS)
        success = false;
  }

  if(success) // If we succeeded, we set the version appropriately
  {
    if(options->regroot.size() > 0)
    {
      InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, options->regroot, "VersionMajor", REG_DWORD }, "", target.Major });
      InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, options->regroot, "VersionMinor", REG_DWORD }, "", target.Minor });
    }
    target.version = payload.target.version;
    return ERR_SUCCESS;
  }
  return ERR_INSTALL_FAILED; // Otherwise we emit an error message and do not set the version
}

int ApplyUpdate(struct Options* options, const char* file, const char* dir)
{
  Payload payload;
  if(file)
  {
    std::ifstream fs(file, std::ios_base::in | std::ios_base::binary);
    return ApplyHop(options, fs, dir, false, false, options->curversion, payload);
  }
  while(options->downloads.size())
  {
    std::ifstream fs(options->downloads.front(), std::ios_base::in | std::ios_base::binary);
    if(ERROR_CODES err = ApplyHop(options, fs, dir, false, false, options->curversion, payload))
      return err; // If something failed, do not attempt to process any further hops, just bail out immediately
    fs.close();
    std::remove(options->downloads.front().c_str());
    options->downloads.erase(options->downloads.begin());
    options->Save(Options::CONFIG_PATH);
  }
  return ERR_SUCCESS;
}

size_t GetTotalSize(const std::vector<PayloadPack>& pack)
{
  size_t sz = 0;
  for(const auto& payload : pack)
  {
    switch(payload.tag())
    {
    case PayloadPack::Type<BinaryPayloadAdd>::value:
      sz += payload.get<BinaryPayloadAdd>().data;
      break;
    case PayloadPack::Type<BinaryPayloadDelta>::value:
      sz += payload.get<BinaryPayloadDelta>().file.data;
      break;
    }
  }
  return sz;
}

int Install(const Options& options, std::istream& fs, const char* targetdir, bool copy, const char* targetpatch, const char* name)
{
  Str curdir = !targetdir ? GetCurrentDir() : targetdir;
  Str patchexe = !targetpatch ? GetCurrentName() : targetpatch;
  Options opt(options);
  Payload payload;

  DynArray<char> test;
  if(ERROR_CODES err = ApplyHop(&opt, fs, curdir, true, true, opt.curversion, payload))
    return err;

#ifdef BSS_PLATFORM_WIN32
  // Populate mandatory installation fields
  Str upname = !name ? payload.details.displayname : name;
  if(!upname.size())
    upname = GetGUID();
  opt.regroot = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + upname;
  if(payload.details.displayname.size() > 0)
    InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "DisplayName", REG_SZ }, payload.details.displayname, 0 });
  if(payload.details.displayname.size() > 0)
    InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "Publisher", REG_SZ }, payload.details.publisher, 0 });
  if(payload.details.displayname.size() > 0)
    InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "HelpLink", REG_SZ }, payload.details.helplink, 0 });
  if(payload.details.displayname.size() > 0)
    InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "URLUpdateInfo", REG_SZ }, payload.details.updateinfourl, 0 });
  if(payload.details.displayname.size() > 0)
    InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "URLInfoAbout", REG_SZ }, payload.details.aboutinfourl, 0 });
  if(payload.details.displayname.size() > 0)
    InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "Comments", REG_SZ }, payload.details.comment, 0 });
  if(payload.details.displayname.size() > 0)
    InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "DisplayIcon", REG_SZ }, curdir + payload.details.mainexe, 0 });

  InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "UninstallString", REG_SZ }, curdir + patchexe + " -x", 0 });
  InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "InstallLocation", REG_SZ }, targetdir, 0 });
  InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "InstallSource", REG_SZ }, GetCurrentDir(), 0 });
  InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "VersionMajor", REG_DWORD }, "", opt.curversion.Major });
  InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "VersionMinor", REG_DWORD }, "", opt.curversion.Minor });
  InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "EstimatedSize", REG_DWORD }, "", GetTotalSize(payload.update) + GetTotalSize(payload.install) });
  InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "NoModify", REG_DWORD }, "", 1 });
  InstallRegistryEntry(RegistryPayloadAdd{ { ROOTKEY_LOCAL_MACHINE, opt.regroot, "NoRepair", REG_DWORD }, "", 1 });
#endif

  // We must then save an options configuration file - the patcher EXE will be placed once we exit this function
  opt.Save(curdir + Options::CONFIG_PATH);

  if(copy)
    CopyFiles(GetCurrentPath(), curdir + GetCurrentName()); // Ignore failure, it just means we tried to overwrite ourselves.
  return ERR_SUCCESS;
}
int Install(const struct Options* options, const char* file, const char* targetdir, char copy)
{
  if(!options)
    return ERR_INVALID_ARGUMENTS;

  if(!file)
  {
    if(!options->downloads.size())
      return ERR_DOWNLOAD_NOT_FOUND;
    file = options->downloads[0];
  }

  std::ifstream fs(file, std::ios_base::in | std::ios_base::binary);
  return Install(*options, fs, targetdir, copy != 0, 0, 0);
}

int Uninstall(const struct Options* options)
{
  for(auto& s : options->downloads) // Delete any temporary files
    std::remove(s.c_str());
  for(auto& s : options->trackfiles) // We delete the directories in the self-deletion code.
    std::remove(s.c_str());
  std::remove(options->selfdownload);
  std::remove(Options::CONFIG_PATH);

#ifdef BSS_PLATFORM_WIN32
  for(auto& s : options->trackreg)
    UninstallRegistryEntry(s);
#endif

  if(!DeleteSelf())
    return ERR_FATAL;
  return ERR_SUCCESS;
}