// Copyright ©2015 Black Sphere Studios

#ifndef __UPATCH_H__
#define __UPATCH_H__

#include "bss-util\bss_compiler.h"
#include "version.h"
#include <ostream>
#include <array>

#ifdef BSS_PLATFORM_WIN32
#include "bss-util/bss_win32_includes.h"
#endif

#include "curl\curl.h"

static const int SELF_VER[4] = { UPATCH_VERSION_MAJOR, UPATCH_VERSION_MINOR, UPATCH_VERSION_REVISION, 0 };
static const char* CFG_PATH = "uPatch.cfg";
static const char* TEMP_EXE_PATH = "~upatch.exe";

enum ERROR_CODES : char
{
  ERR_SUCCESS = 0, // Successful execution, but no operation was taken (no update necessary)
  ERR_UPDATE_AVAILABLE = 1,
  ERR_DOWNLOAD_COMPLETE = 2,
  ERR_INSTALL_COMPLETE = 3,
  ERR_SELF_UPDATE_AVAILABLE = 4,
  ERR_SELF_DOWNLOAD_COMPLETE = 5,
  ERR_SELF_INSTALL_COMPLETE = 6,
  ERR_UPDATE_DOWNLOADED = 7,
  ERR_SELF_UPDATE_DOWNLOADED = 8,
  ERR_FATAL = -1, // Generic fatal error
  ERR_CANT_FIND_CONTROL_FILE = -2,
  ERR_CANT_DOWNLOAD_CONTROL_FILE = -3,
  ERR_INVALID_CONTROL_FILE = -4,
  ERR_NO_VALID_MIRRORS = -5,
  ERR_DOWNLOAD_NOT_FOUND = -6,
  ERR_DOWNLOAD_ACCESS_DENIED = -7,
  ERR_DOWNLOAD_INTERRUPTED = -8,
  ERR_DOWNLOAD_CORRUPT = -9,
  ERR_INSTALL_FAILED = -10,
  ERR_CURL_FAILURE = -11,
  ERR_NO_UPDATE_PATH = -12,
};

enum MODE : char
{
  MODE_CHECK = 0,
  MODE_DOWNLOAD = 1,
  MODE_UPDATE = 2,
  MODE_PACK = 3,
  MODE_UNINSTALL = 4,
  MODE_UNINSTALL_WAIT = 5,
  MODE_NONE = -1,
};

enum PAYLOAD : char
{
  PAYLOAD_ADD = 0,
  PAYLOAD_DELTA,
  PAYLOAD_REMOVE,
  PAYLOAD_ADDREG,
  PAYLOAD_REMOVEREG,
  PAYLOAD_INSTALLINFO,
};

typedef int(*progresscallback)(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);

extern bool DeleteSelf();
extern char ToControlError(char err);
extern char DownloadFile(const char* url, std::ostream& s, curl_progress_callback* callback = 0, void* data = 0);
extern bool ExecuteProcess(char* str);
extern char cmpver(const int(&o)[4], const int(&n)[4]);
extern char cmpver(const std::array<int, 4>& o, const std::array<int, 4>& n);
extern char packdelta(std::istream& ofile, std::istream& nfile, std::ostream& out);
extern char applydelta(std::istream& delta, std::istream& file, std::ostream& out);
extern char packzip(std::istream& in, std::ostream& out, char level = 9);
extern char unpackzip(std::istream& in, std::ostream& out);
extern void calcmd5(std::istream& in, unsigned char(&out)[16]);
extern bool CheckWritePermission(const char* file);

#endif