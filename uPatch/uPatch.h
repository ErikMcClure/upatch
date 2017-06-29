// Copyright ©2017 Black Sphere Studios

#ifndef __UPATCH_H__
#define __UPATCH_H__

#include "bss-util/compiler.h"
#include "version.h"

typedef unsigned char MD5HASH[16];
struct Options;
struct Source;

#ifdef  __cplusplus
extern "C" {
#endif
  extern bssVersionInfo uPatchVersion;

  enum ERROR_CODES
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
    ERR_REQUESTED_ADMIN_RIGHTS = 9,
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
    ERR_NO_ACTION_REQUESTED = -13,
    ERR_INVALID_ARGUMENTS = -14,
    ERR_ZLIB_FAILURE = -15,
    ERR_TARGET_MISMATCH = -16,
    ERR_INSTALL_ACCESS_DENIED = -17,
  };

  UPATCH_EXTERN int CheckUpdate(const struct Options* options, struct Source* out);
  UPATCH_EXTERN int DownloadUpdate(struct Options* options, const Source* src);
  UPATCH_EXTERN int ApplyUpdate(struct Options* options, const char* file, const char* targetdir);
  UPATCH_EXTERN int CheckSelfUpdate(const struct Options* options, Source* out);
  UPATCH_EXTERN int DownloadSelfUpdate(struct Options* options, const Source* src, const char* file);
  UPATCH_EXTERN int ApplySelfUpdate(struct Options* options, const char* file);
  UPATCH_EXTERN int Install(const struct Options* options, const char* file, const char* targetdir, char copy);
  UPATCH_EXTERN int Uninstall(const struct Options* options);

#ifdef  __cplusplus
}
#endif

#endif