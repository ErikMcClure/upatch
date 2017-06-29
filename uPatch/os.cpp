// Copyright ©2017 Black Sphere Studios

#include "os.h"
#include "Options.h"
#include "bss-util/compiler.h"
#include "bss-util/os.h"
#include <fstream>

#ifdef BSS_PLATFORM_WIN32
#include "bss-util/win32_includes.h"
#include <Shellapi.h>
#include <Rpc.h>
#else

#endif
bool upatch::DeleteSelf()
{
#ifdef BSS_PLATFORM_WIN32
  wchar_t buf[2048];
  GetModuleFileNameW(0, buf, 2048);
  CopyFileW(buf, Options::TEMP_EXE_PATH_W, FALSE);
  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;

  HANDLE hFile = CreateFileW(Options::TEMP_EXE_PATH_W, 0, FILE_SHARE_READ | FILE_SHARE_DELETE, &sa, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, 0);
  bss::StrW cmd = bss::StrWF(L"\"%s\" -w %i -x \"%s\"", Options::TEMP_EXE_PATH_W, GetCurrentProcessId(), buf);
  STARTUPINFOW startinfo = { 0 };
  startinfo.cb = sizeof(STARTUPINFOW);
  PROCESS_INFORMATION procinfo = { 0 };
  if(!CreateProcessW(Options::TEMP_EXE_PATH_W, cmd.UnsafeString(), 0, 0, TRUE, NORMAL_PRIORITY_CLASS, 0, 0, &startinfo, &procinfo))
  {
    UPLOG(1, "Could not start temporary file!");
    return false;
  }
  HANDLE hProc = OpenProcess(SYNCHRONIZE, FALSE, procinfo.dwProcessId);
  WaitForInputIdle(hProc, INFINITE);
  CloseHandle(hProc);
  CloseHandle(hFile);
#else // POSIX

#endif
  return true;
}

bool upatch::CopyFiles(const char* src, const char* dest, bool overwrite)
{
  return CopyFileW(bss::StrW(src), bss::StrW(dest), !overwrite) != 0;
}

bool upatch::ExecuteProcess(const char* str)
{
#ifdef BSS_PLATFORM_WIN32
  STARTUPINFOW si = { 0 };
  si.cb = sizeof(STARTUPINFOW);
  PROCESS_INFORMATION pi = { 0 };
  bss::StrW commandline(str);
  if(!CreateProcessW(0, commandline.UnsafeString(), 0, 0, FALSE, NORMAL_PRIORITY_CLASS, 0, 0, &si, &pi))
  {
    UPLOG(1, "Could not execute ", commandline.c_str());
    return false;
  }
#endif
  return true;
}

bss::Str upatch::GetCurrentPath()
{
#ifdef BSS_PLATFORM_WIN32
  wchar_t buf[MAX_PATH];
  GetModuleFileNameW(0, buf, MAX_PATH);
  return bss::Str(buf);
#else //POSIX

#endif
}

unsigned long upatch::GetCurrentPID()
{
  return GetCurrentProcessId();
}

void upatch::UninstallSelf(const char* file)
{
#ifdef BSS_PLATFORM_WIN32
  bss::StrW wfile(file);
  DeleteFileW(wfile);

  if(wchar_t* p = wcsrchr(wfile.UnsafeString(), L'/'))
    p[0] = 0;
  if(wchar_t* p = wcsrchr(wfile.UnsafeString(), L'\\'))
    p[0] = 0;
  bss::DelDirW(wfile.c_str(), true);

  STARTUPINFOA si = { 0 };
  si.cb = sizeof(STARTUPINFOA);
  PROCESS_INFORMATION pi = { 0 };
  CreateProcessA(NULL, "notepad", NULL, NULL, TRUE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);
#endif
}

#ifdef BSS_PLATFORM_WIN32
namespace upatch {
  HKEY GetRootKey(WIN32_ROOTKEY key)
  {
    switch(key)
    {
    case ROOTKEY_CLASSES_ROOT: return HKEY_CLASSES_ROOT;
    case ROOTKEY_CURRENT_USER: return HKEY_CURRENT_USER;
    case ROOTKEY_LOCAL_MACHINE: return HKEY_LOCAL_MACHINE;
    case ROOTKEY_USERS: return HKEY_USERS;
    case ROOTKEY_PERFORMANCE_DATA: return HKEY_PERFORMANCE_DATA;
    case ROOTKEY_PERFORMANCE_TEXT: return HKEY_PERFORMANCE_TEXT;
    case ROOTKEY_PERFORMANCE_NLSTEXT: return HKEY_PERFORMANCE_NLSTEXT;
    case ROOTKEY_CURRENT_CONFIG: return HKEY_CURRENT_CONFIG;
    case ROOTKEY_DYN_DATA: return HKEY_DYN_DATA;
    case ROOTKEY_CURRENT_USER_LOCAL_SETTINGS: return HKEY_CURRENT_USER_LOCAL_SETTINGS;
    }
    return HKEY_CURRENT_USER;
  }
}
#endif

bool upatch::UninstallRegistryEntry(const RegistryPayloadRemove& entry)
{
  UPLOG(4, "Removing registry entry at: ", entry.root, "/", entry.path);
#ifdef BSS_PLATFORM_WIN32
  if(bss::DelRegistryNode(GetRootKey(entry.root), entry.path))
    return true;
#endif
  UPLOG(2, "Failed to remove registry entry ", entry.path);
  return false;
}

bool upatch::InstallRegistryEntry(const RegistryPayloadAdd& entry)
{
  bool 	ret = false;
#ifdef BSS_PLATFORM_WIN32
  DWORD	dwDisposition;
  HKEY hTempKey = (HKEY)0;
  bss::StrW name(entry.entry.name);

  UPLOG(4, "Installing registry entry at: ", entry.entry.root, "/", entry.entry.path, "/", entry.entry.name);
  if(RegCreateKeyExW(GetRootKey(entry.entry.root), bss::StrW(entry.entry.path).c_str(), 0, 0, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, 0, &hTempKey, &dwDisposition) == ERROR_SUCCESS)
  {
    switch(entry.entry.type)
    {
    case REG_DWORD:
      ret = RegSetValueExW(hTempKey, name.c_str(), 0, REG_DWORD, (LPBYTE)&entry.idata, sizeof(DWORD)) == ERROR_SUCCESS;
    case REG_QWORD:
      ret = RegSetValueExW(hTempKey, name.c_str(), 0, REG_QWORD, (LPBYTE)&entry.idata, sizeof(uint64_t)) == ERROR_SUCCESS;
    case REG_BINARY:
      ret = RegSetValueExW(hTempKey, name.c_str(), 0, REG_BINARY, (LPBYTE)entry.sdata.data(), entry.sdata.size()) == ERROR_SUCCESS;
    default:
    {
      bss::StrW data(entry.sdata);
      ret = RegSetValueExW(hTempKey, name.c_str(), 0, entry.entry.type, (LPBYTE)data.c_str(), ((DWORD)data.size() + 1) * sizeof(wchar_t)) == ERROR_SUCCESS;
    }
    }
  }

  // close opened key
  if(hTempKey)
    ::RegCloseKey(hTempKey);

  if(!ret)
    UPLOG(2, "Failed to install registry entry ", entry.entry.name);

#endif
  return ret;
}

bool upatch::HasAdmin()
{
  bool ret = false;
#ifdef BSS_PLATFORM_WIN32
  HANDLE hToken = NULL;

  if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
  {
    TOKEN_ELEVATION Elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);

    if(GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
      ret = Elevation.TokenIsElevated != 0;
  }

  if(hToken)
    CloseHandle(hToken);
#endif

  return ret;
}

void upatch::RestartWithAdmin(int argc, char** argv)
{
  bss::Str args;
  for(int i = 0; i < argc;)
  {
    args += argv[i];
    if(++i < argc)
      args += " ";
  }
  RestartWithAdmin(args);
}
void upatch::RestartWithAdmin(const char* arguments)
{
#ifdef BSS_PLATFORM_WIN32
  UPLOG(3, "Restarting with admin privileges");
  ShellExecuteW(NULL, L"runas", bss::StrW(GetCurrentPath()), bss::StrW(arguments), NULL, SW_SHOWNORMAL);
#endif
}
bss::Str upatch::GetGUID()
{
#ifdef BSS_PLATFORM_WIN32
  GUID out;
  UuidCreate(&out);
#endif
  unsigned short* data4 = reinterpret_cast<unsigned short*>(out.Data4);
  return bss::StrF("{%08X-%04hX-%04hX-%04hX-%04hX%04hX%04hX}", out.Data1, out.Data2, out.Data3, out.Data4[0], out.Data4[1], out.Data4[2], out.Data4[3]);
}