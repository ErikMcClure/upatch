// Copyright ©2017 Black Sphere Studios

#include "Payload.h"
#include "Util.h"
#include "Source.h"
#include "Options.h"
#include "os.h"
#include "bss-util/os.h"
#include "bss-util/stream.h"
#include "bss-util/JSON.h"
#include "curl/curl.h"
#include <iostream>
#include <fstream>

using namespace bss;
using namespace upatch;

//#ifdef BSS_CPU_x86_64
//#pragma comment(linker, "/NODEFAULTLIB:LIBCMT")
//#pragma comment(lib, "ws2_64.lib")
//#else
//#pragma comment(linker, "/NODEFAULTLIB:LIBCMT")
//#ifdef BSS_DEBUG
//#pragma comment(linker, "/NODEFAULTLIB:MSVCRT")
//#endif
//#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "../lib/libcurl_a.lib")
//#pragma comment(lib, "../lib/zlib.lib")
//#endif

struct ModeNone {};
struct ModeCheck {};
struct ModeDownload { };
struct ModeUpdate { Str file; Str dir; };
struct ModePack { Str from; Str to; bssVersionInfo vfrom; bssVersionInfo vto; Str reg; InstallPayload details; Str out; };
struct ModeInstall { Str file; Str dir; };
struct ModeUninstall {};
struct ModeUninstallSelf { Str file; };

typedef bss::Variant<ModeNone, ModeCheck, ModeDownload, ModeUpdate, ModePack, ModeInstall, ModeUninstall, ModeUninstallSelf> PatchMode;

bssVersionInfo ParseVersionInfo(const char* s)
{
  bssVersionInfo v = { 0,0,0,0 };
  char* context;
  v.Major = strtoul(s, &context, 10);
  if(context && context[0] != 0)
    v.Minor = strtoul(context + 1, &context, 10);
  if(context && context[0] != 0)
    v.Revision = strtoul(context + 1, &context, 10);
  if(context && context[0] != 0)
    v.Build = strtoul(context + 1, &context, 10);
  return v;
}

struct RuntimeOptions
{
  bool HideGUI;
  bool RequestAdmin;
  uint64_t WaitPID;
  Str Execute;
};

int ExecuteMode(const PatchMode& mode, Options& opt)
{
  int err;
  switch(mode.tag())
  {
  case PatchMode::Type<ModeNone>::value:
  case PatchMode::Type<ModeCheck>::value:
    if(CheckSelfUpdate(&opt, 0) == ERR_SELF_UPDATE_AVAILABLE)
      return ERR_SELF_UPDATE_AVAILABLE;
    break;
  default:
    if((err = ApplySelfUpdate(&opt, 0)) > 0) // Ignore self-update errors because we can still function
      return err;
    break;
  }

  switch(mode.tag())
  {
  case PatchMode::Type<ModeNone>::value:
    return ERR_NO_ACTION_REQUESTED;
  case PatchMode::Type<ModeCheck>::value:
    return CheckUpdate(&opt, 0);
  case PatchMode::Type<ModeDownload>::value:
    return DownloadUpdate(&opt, 0);
  case PatchMode::Type<ModeUpdate>::value:
    return ApplyUpdate(&opt, mode.get<ModeUpdate>().file, mode.get<ModeUpdate>().dir);
  case PatchMode::Type<ModePack>::value:
  {
    const ModePack& pack = mode.get<ModePack>();
    Payload payload;
    payload.from = pack.vfrom;
    payload.target = pack.vto;
    payload.details = pack.details;
    payload.admin = false;
    std::ofstream fs(!pack.out.size() ? "deltapack.ubj.zip" : pack.out, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
    return CreatePatch(pack.from, pack.to, pack.reg, payload, fs);
  }
  case PatchMode::Type<ModeInstall>::value:
    return Install(&opt, mode.get<ModeInstall>().file, mode.get<ModeInstall>().dir, true);
  case PatchMode::Type<ModeUninstall>::value:
    return Uninstall(&opt);
  case PatchMode::Type<ModeUninstallSelf>::value:
    UninstallSelf(mode.get<ModeUninstallSelf>().file);
    return ERR_SUCCESS;
  }

  return ERR_FATAL;
}

void ShowGUI()
{
#ifdef BSS_PLATFORM_WIN32
  AllocConsole();
  freopen("CONOUT$", "wb", stdout);
  freopen("CONOUT$", "wb", stderr);
  freopen("CONIN$", "rb", stdin);
#endif
}

int main(int argc, char** argv)
{
  PatchMode mode(ModeNone{});
  RuntimeOptions runtime = { false, false, (uint64_t)~0 };
  
  ForceWin64Crash();
  SetWorkDirToCur();
  Options options(Options::CONFIG_PATH); // This is what we'll modify and write back to upatch.cfg
  curl_global_init(CURL_GLOBAL_DEFAULT);
  Options::log.AddTarget(std::cout);
  Options::log.AddTarget("upatch.log");

  ProcessCmdArgs(argc, argv, [&](const char* const* p, size_t n) {
    switch(p[0][1])
    {
    case 'c': // Check for update
      mode = ModeCheck{};
     break; 
    case 'd': // Check for update and download it, returning zero once it has successfully downloaded
      mode = ModeDownload{};
      break; 
    case 'u': // Check for update, check if already downloaded, install update
      mode = ModeUpdate{ (n > 1) ? p[1] : "", (n > 2) ? p[2] : "" };
      break;
    case 'w': // Wait until the given process has exited before starting operation
      if(n>1)
        runtime.WaitPID = atoi(p[1]); 
      break;
    case 'e': // execute the given command after operation has completed
      if(n>1)
        runtime.Execute = p[1]; 
      break;
    case 'p': // Pack the given directory into a .ubj.gz file, or compare two directories or packed files and produce a delta pack for them.
      if(!mode.is<ModePack>())
        mode = ModePack{};
      if(n>1) mode.get<ModePack>().from = p[1];
      if(n>2) mode.get<ModePack>().to = p[2];
      break; 
    case 'v': // Sets the to and from versions for a delta pack, respectively
      if(!mode.is<ModePack>())
        mode = ModePack{};
      if(n>1) mode.get<ModePack>().vto = ParseVersionInfo(p[1]); // target version
      if(n>2) mode.get<ModePack>().vfrom = ParseVersionInfo(p[2]); // "from" version, if not specified, set to 0.0.0.0
      break;
    case 'o': // Overrides the specified option with the given value.
      if(n <= 2) break;
      options.OverrideOptions(p, n);
      break;
    case 'r': // embeds a set of registry modifications
      if(!mode.is<ModePack>())
        mode = ModePack{};
      if(n>1) mode.get<ModePack>().reg = p[1];
      break;
    case 'g': // Shortcut to generating installation registry entries
      if(!mode.is<ModePack>())
        mode = ModePack{};
      for(uint32_t i = 1; i < n; ++i)
        mode.get<ModePack>().details[i - 1] = p[i];
      break;
    case 's': // Executes a self-update by copying this EXE to the specified path
      if(n > 1)
      {
        std::remove(p[1]);
        std::rename(GetCurrentPath().c_str(), p[1]);
      }
      break;
    case 'x': //uninstalls all tracked files and deletes itself
      if(n < 1)
        mode = ModeUninstallSelf{ p[1] };
      else
        mode = ModeUninstall{};
      break;
    case 'h': runtime.HideGUI = true; break;
    case 'a': runtime.RequestAdmin = true; break;
    case 'i': mode = ModeInstall{ (n > 1) ? p[1] : "", (n > 2) ? p[2] : "" }; break;
    }
  });

  if(runtime.WaitPID != (uint64_t)~0)
  {
#ifdef BSS_PLATFORM_WIN32
    UPLOG(4, "Waiting for ", runtime.WaitPID);
    HANDLE hProc = OpenProcess(SYNCHRONIZE, FALSE, runtime.WaitPID);
    WaitForSingleObject(hProc, INFINITE);
    CloseHandle(hProc);
#else // POSIX

#endif
  }

  if(runtime.RequestAdmin && !HasAdmin())
  {
    RestartWithAdmin(argc, argv);
    return ERR_REQUESTED_ADMIN_RIGHTS;
  }
  if(!runtime.HideGUI)
    ShowGUI();

  int retval = ExecuteMode(mode, options);
  if(retval == ERR_REQUESTED_ADMIN_RIGHTS) // If we restarted with admin rights, we do NOT execute any commands because we'll do it once we restart.
    return ERR_REQUESTED_ADMIN_RIGHTS;

  if(runtime.Execute.length() > 0)
  {
    UPLOG(4, "Executing command ", runtime.Execute);
    if(!ExecuteProcess(runtime.Execute.UnsafeString()))
      retval = ERR_FATAL;
  }

  return retval;
}

struct HINSTANCE__;

// WinMain function, simply a catcher that calls the main function
int __stdcall WinMain(HINSTANCE__* hInstance, HINSTANCE__* hPrevInstance, char* lpCmdLine, int nShowCmd)
{
  int argc = ToArgV<char>(0, lpCmdLine);
  std::unique_ptr<char*[]> argv(new char*[argc]);
  ToArgV<char>(argv.get(), lpCmdLine);
  return main(argc, argv.get());
}