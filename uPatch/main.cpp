// Copyright ©2015 Black Sphere Studios

#include "payload.h"
#include "bss-util/bss_util.h"
#include "bss-util/bss_algo.h"
#include "bss-util/cStr.h"
#include "bss-util/cHash.h"
#include "bss-util/cTrie.h"
#include "bss-util/cJSON.h"
#include "bss-util/cUBJSON.h"
#include "bss-util/os.h"
#include <iostream>
#include <fstream>

using namespace bss_util;

#if defined(BSS_DEBUG) && defined(BSS_CPU_x86_64)
#pragma comment(lib, "../lib/bss-util64_s_d.lib")
#elif defined(BSS_CPU_x86_64)
#pragma comment(lib, "../lib/bss-util64_s.lib")
#elif defined(BSS_DEBUG)
#pragma comment(lib, "../lib/bss-util_s_d.lib")
#else
#pragma comment(lib, "../lib/bss-util_s.lib")
#endif

#ifdef BSS_CPU_x86_64
#pragma comment(linker, "/NODEFAULTLIB:LIBCMT")
#pragma comment(lib, "ws2_64.lib")
#else
#pragma comment(linker, "/NODEFAULTLIB:LIBCMT")
#ifdef BSS_DEBUG
#pragma comment(linker, "/NODEFAULTLIB:MSVCRT")
#endif
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "../lib/libcurl_a.lib")
#pragma comment(lib, "../lib/zlib.lib")
#endif

struct Source
{
  struct Hop
  {
    int from[4];
    int to[4];
    cStr md5;
    std::vector<cStr> mirrors;

    void EvalJSON(const char* id, std::istream& s)
    {
      static cTrie<char> t(4, "from", "to", "md5", "mirrors");
      switch(t[id])
      {
      case 0: ParseJSON(from, s); break;
      case 1: ParseJSON(to, s); break;
      case 2: ParseJSON(md5, s); break;
      case 3: ParseJSON(mirrors, s); break;
      }
    }
  };
  
  int version[4];
  std::vector<Hop> hops;

  void EvalJSON(const char* id, std::istream& s)
  {
    static cTrie<char> t(2, "version", "hops");
    switch(t[id])
    {
    case 0: ParseJSON(version, s); break;
    case 1: ParseJSON(hops, s); break;
    }
  }
};

static cTrie<short> OptTrie(8, "version", "self", "target", "download", "selfdownload", "trackfiles", "trackreg", "maxconcurrent");

struct Options
{
  int version[4]; // major, minor, revision, build, zero'd if not used.
  cStr self;
  cStr target;
  std::vector<cStr> download;
  cStr selfdownload;
  std::vector<cStr> trackfiles;
  std::vector<cStr> trackreg;
  int maxconcurrent;

  void EvalJSON(const char* id, std::istream& s)
  {
    switch(OptTrie[id])
    {
    case 0: ParseJSON(version, s); break;
    case 1: ParseJSON(self, s); break;
    case 2: ParseJSON(target, s); break;
    case 3: ParseJSON(download, s); break;
    case 4: ParseJSON(selfdownload, s); break;
    case 5: ParseJSON(trackfiles, s); break;
    case 6: ParseJSON(trackreg, s); break;
    case 7: ParseJSON(maxconcurrent, s); break;
    }
  }

  void SerializeJSON(std::ostream& s, unsigned int& pretty) const
  {
    WriteJSON(version, s, pretty);
    WriteJSON(self, s, pretty);
    WriteJSON(target, s, pretty);
    WriteJSON(download, s, pretty);
    WriteJSON(selfdownload, s, pretty);
    WriteJSON(trackfiles, s, pretty);
    WriteJSON(trackreg, s, pretty);
    WriteJSON(maxconcurrent, s, pretty);
  }
};

void LoadOptions(Options& opt)
{
  std::fstream fs(CFG_PATH, std::ios_base::in | std::ios_base::binary);
  if(fs)
  {
    ParseJSON<Options>(opt, fs);
    fs.close();
  }
}

void OverrideOptions(Options& opt, const char* const* p, size_t n)
{
  switch(OptTrie[p[1]])
  {
  case 0:
  {
    int c = 0;
    for(cStr& i : cStr::Explode('.', p[2]))
    {
      opt.version[c++] = atoi(i);
      if(c > 3) break;
    }
    break;
  }
  case 1: opt.self = p[2]; break;
  case 2: opt.target = p[2]; break;
  case 3:
    for(uint i = 1; i < n; ++i)
      opt.download.push_back(p[i]);
    break;
  case 4: opt.selfdownload = p[2];
  case 5:
    for(uint i = 1; i < n; ++i)
      opt.trackfiles.push_back(p[i]);
    break;
  case 7: opt.maxconcurrent = atoi(p[2]); break;
  }
}

char LoadSource(Source& src, const char* url)
{
  std::stringstream ss(std::ios_base::out | std::ios_base::in | std::ios_base::binary);
  char r = DownloadFile(url, ss);
  if(r != ERR_SUCCESS) return ToControlError(r);

  try {
    ParseJSON<Source>(src, ss);
  }
  catch(std::runtime_error e)
  {
    return ERR_INVALID_CONTROL_FILE;
  }
  return ERR_SUCCESS;
}

char do_check(Options& opt, Source& self, Source& target)
{
  if(opt.download.size() > 0)
    return ERR_UPDATE_DOWNLOADED;
  if(opt.selfdownload.size() > 0)
    return ERR_SELF_UPDATE_DOWNLOADED;

  char r = LoadSource(self, opt.self);
  if(r != ERR_SUCCESS) return r;
  r = LoadSource(target, opt.target);
  if(r != ERR_SUCCESS) return r;

  if(cmpver(opt.version, target.version) < 0)
    return ERR_UPDATE_AVAILABLE;
  else if(cmpver(SELF_VER, self.version) < 0)
    return ERR_SELF_UPDATE_AVAILABLE;
  return ERR_SUCCESS;
}

template<typename T, int I>
std::array<T, I> build_array(const T(&a)[I])
{
  std::array<T, I> r;
  for(size_t i = 0; i < I; ++i) r[i] = a[i];
  return r;
}

typedef std::pair<std::array<int, 4>, Source::Hop*> HopPair;

void r_find_hops(const std::array<int, 4>& v, Source::Hop* h, std::vector<HopPair>& edges, std::vector<Source::Hop*>& out)
{
  if(h->mirrors.empty()) return; // If we have no valid mirrors this whole chain is invalid
  auto iter = std::lower_bound(edges.begin(), edges.end(), v, [](HopPair& a, const std::array<int, 4>& b) -> bool { return cmpver(b, a.first) < 0; });

  for(; !cmpver(iter->first, v); ++iter)
  {
    r_find_hops(build_array(iter->second->to), iter->second, edges, out);
    if(!out.empty())
    {
      out.push_back(h);
      return;
    }
  }
}

void find_hops(const int (&version)[4], Source& src, std::vector<Source::Hop*>& list)
{
  if(cmpver(version, src.version) >= 0)
    return; // There's nothing to update!

  std::vector<HopPair> bases; // List of base versions. We start with our version, then work down the list of available full updates.
  std::vector<HopPair> edges; // list of version hops in [from, hop*] form.

  for(Source::Hop& h : src.hops)
  {
    if(!h.from[0] && !h.from[1] && !h.from[2] && !h.from[3])
      bases.push_back(HopPair(build_array(h.to), &h));
    else
      bases.push_back(HopPair(build_array(h.from), &h));
  }

  std::sort(bases.begin(), bases.end(), [](HopPair& a, HopPair& b) { return cmpver(b.first, a.first); });
  std::sort(edges.begin(), edges.end(), [](HopPair& a, HopPair& b) { char r = cmpver(b.first, a.first); return !r ? cmpver(b.second->to, a.second->to) : r; });
  bases.insert(bases.begin(), HopPair(build_array(version), 0)); // insert current version before sorted elements

  std::vector<Source::Hop*> hops;
  for(HopPair& pair : bases)
  {
    r_find_hops(pair.first, pair.second, edges, hops);
    if(!hops.empty())
      break;
  }

  bssreverse(hops.data(), hops.size());
  list = hops;
}

void find_downloads(const int(&version)[4], std::vector<Source::Hop*>& dls, Source& self, Source& target)
{
  find_hops(SELF_VER, self, dls);
  if(!dls.size())
    dls.push_back(0);
  find_hops(version, target, dls);
}

bool checkMD5(std::istream& s, Source::Hop* hop)
{
  unsigned char md5[16];
  unsigned char md5_comp[16];

  calcmd5(s, md5);
  if(Base64Decode(hop->md5, hop->md5.size(), 0) == 16)
  {
    Base64Decode(hop->md5, hop->md5.size(), md5_comp);
    return !memcmp(md5, md5_comp, 16);
  }
  return false;
}

// We only write out the real file name to the options once it has actually been downloaded and verified
char do_downloads(std::vector<Source::Hop*>& dls, Options& optbase)
{
  assert(dls.size() > 0);
  char ret = ERR_SUCCESS;

  if(dls[0] != 0)
  {
    const char* SELF_PATH = "~selfupdate.dlcache";
    DownloadFile(dls[0]->mirrors[0], std::fstream(SELF_PATH, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc));
    if(checkMD5(std::fstream(SELF_PATH, std::ios_base::in | std::ios_base::binary), dls[0]))
      optbase.selfdownload = SELF_PATH;
    else
      ret = ERR_DOWNLOAD_CORRUPT;
  }
  for(size_t i = 1; i < dls.size(); ++i)
  {
    static const cStr path(cStrF("~update%i.dlcache", i));
    DownloadFile(dls[i]->mirrors[0], std::fstream(path.c_str(), std::ios_base::out | std::ios_base::binary | std::ios_base::trunc));
    if(checkMD5(std::fstream(path.c_str(), std::ios_base::in | std::ios_base::binary), dls[i]))
      optbase.selfdownload = path;
    else
      ret = ERR_DOWNLOAD_CORRUPT;
  }

  return ret;
}

void SaveOptions(Options& opt, const char* file)
{
  std::fstream fs(file, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
  WriteJSON<Options>(opt, fs, 1);
  fs.close();
}

char ApplyUpdate(const char* file, bool install)
{
  char ret = ERR_SUCCESS;
  cStr ofile(file);
  ofile += ".inflate";
  ret = unpackzip(std::fstream(file, std::ios_base::in | std::ios_base::binary),
    std::fstream(ofile, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc));
  if(!ret)
  {
    PayloadPack pack;
    try
    {
      ParseUBJSON(pack, std::fstream(ofile, std::ios_base::in | std::ios_base::binary), 0);
      //pack.admin TODO: if admin privileges are necessary, start an admin version and bail out
      std::vector<cStr> deltas;
      bool valid = true;
      unsigned char md5[16];
      for(auto& v : pack.update)
      {
        if(v.type == PAYLOAD_DELTA)
        {
          BinaryPayload& p = v.payload.get<BinaryPayload>();
          cStr temp = p.path + ".upatch_delta";
          applydelta(p.file,
            std::fstream(p.path, std::ios_base::in | std::ios_base::binary),
            std::fstream(temp, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc));
          calcmd5(std::fstream(temp, std::ios_base::in | std::ios_base::binary), md5);
          valid = !memcmp(md5, p.md5, 16);
          if(!valid) break;
        }
      }
      if(valid)
      {
        for(auto& v : pack.update)
        {
          
        }
      }
      else
      {
        for(auto& s : deltas)
          std::remove(s);
        ret = ERR_INSTALL_FAILED;
      }
    }
    catch(std::runtime_error e)
    {
      ret = ERR_DOWNLOAD_CORRUPT;
    }
  }

  std::remove(ofile);
  if(!ret) std::remove(file); // remove the download cache'd file ONLY if we succeeded.
  return ret;
}

void TriggerSelfUpdate()
{

}

int main(int argc, char** argv)
{
  MODE mode = MODE_NONE;
  cStr path1;
  cStr path2;
  cStr reg1;
  cStr reg2;
  cStr wait;
  cStr execute;
  cStr selfupdate;
  Options optbase; // This is what we'll modify and write back to upatch.cfg
  Options opt; // This stores overriden options
  char level = 9;
  std::vector<cStr> installer;
  std::vector<Source::Hop*> dls;
  char forcegui = -1;
  char retval = ERR_SUCCESS;
  bool admin = false;
  bool install = false;

  ForceWin64Crash();
  SetWorkDirToCur();
  LoadOptions(optbase);
  opt = optbase;
  curl_global_init(CURL_GLOBAL_DEFAULT);

  ProcessCmdArgs(argc, argv, [&](const char* const* p, size_t n) {
    switch(p[0][1])
    {
    case 'c': mode = MODE_CHECK; break; // Check for update
    case 'd': mode = MODE_DOWNLOAD; if(n>1) path1 = p[1]; break; // Check for update and download it, returning zero once it has successfully downloaded
    case 'u': // Check for update, check if already downloaded, install update
      if(n > 1) path1 = p[1]; // Overrides what pack file to use
      if(n > 1) path2 = p[2]; // Normally the update is executed on the directory the EXE is in, but this overrides it.
      mode = MODE_UPDATE;
      break; 
    case 'w': if(n>1) wait = p[1]; // Wait until the given process has exited before starting operation
    case 'e': if(n>1) execute = p[1]; // execute the given command after operation has completed
    case 'p': // Pack the given directory into a .ubj.gz file, or compare two directories or packed files and produce a delta pack for them.
      if(n>1) path1 = p[1];
      if(n>2) path2 = p[2];
      mode = MODE_PACK;
      break; 
    case 'o': // Overrides the specified option with the given value.
      if(n <= 2) break;
      OverrideOptions(opt, p, n);
      break;
    case 's': // Executes a self-update by copying this EXE to the specified path
      if(n>1) selfupdate = p[1];
      break;
    case 'r': // embeds a set of registry modifications, or compares two registry modifications and embeds the difference between them.
      if(n>1) reg1 = p[1]; 
      if(n>2) reg2 = p[2];
      mode = MODE_PACK; // This is the same pack mode as -p
      break;
    case 'x': //uninstalls all tracked files and deletes itself
      if(n>1) path1 = p[1];
      if(n>2) path2 = p[2];
      mode = (n>1)?MODE_UNINSTALL_WAIT:MODE_UNINSTALL;
      break; 
    case 'i': // Shortcut to generating installation registry entries
      for(uint i = 1; i < n; ++i)
        installer.push_back(p[i]);
      mode = MODE_PACK;
      break;
    case 'g': forcegui = atoi(p[1]); break;
    case 'a': admin = true; break;
    case 'n': install = true; break;
    case 'l': level = atoi(p[1]); break;
    }
  });

  if(wait)
  {
#ifdef BSS_PLATFORM_WIN32
    HANDLE hProc = OpenProcess(SYNCHRONIZE, FALSE, atoi(wait));
    WaitForSingleObject(hProc, INFINITE);
    CloseHandle(hProc);
#else // POSIX

#endif
  }

  Source self;
  Source target;

  switch(mode)
  {
  case MODE_CHECK:
    retval = do_check(opt, self, target);
    break;
  case MODE_DOWNLOAD:
    retval = do_check(opt, self, target);
    if(retval <= 0 || retval == ERR_UPDATE_DOWNLOADED || retval == ERR_SELF_UPDATE_DOWNLOADED)
      break;
    find_downloads(opt.version, dls, self, target);
    do_downloads(dls, optbase);
    SaveOptions(optbase, CFG_PATH);
    retval = ERR_DOWNLOAD_COMPLETE;
    break;
  case MODE_UPDATE:
    retval = do_check(opt, self, target);
    if(retval <= 0)
      break;
    if(retval != ERR_UPDATE_DOWNLOADED && retval != ERR_SELF_UPDATE_DOWNLOADED)
    {
      find_downloads(opt.version, dls, self, target);
      do_downloads(dls, optbase);
      SaveOptions(optbase, CFG_PATH);
      retval = ERR_DOWNLOAD_COMPLETE;
    }

    if(optbase.selfdownload.size() > 0)
    {
      TriggerSelfUpdate();
      return ERR_SUCCESS;
    }

    for(auto& s : opt.download)
      ApplyUpdate(s, install);
    retval = ERR_INSTALL_COMPLETE;
    break;
  case MODE_UNINSTALL:
  {
    for(auto& s : opt.trackfiles)
    {
      std::remove(s.c_str());
      strrchr(s.ReplaceChar('\\', '/').UnsafeString(), '/')[0] = 0;
      DelDir(s.c_str(), false);
    }
    std::remove(CFG_PATH);

#ifdef BSS_PLATFORM_WIN32
    for(auto& s : opt.trackreg)
    {

    }
#endif

    if(!DeleteSelf())
      return ERR_FATAL;
    return ERR_SUCCESS;
  }
  case MODE_UNINSTALL_WAIT:
  {
#ifdef BSS_PLATFORM_WIN32
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION|SYNCHRONIZE, FALSE, atoi(path1));
    WaitForSingleObject(hProc, INFINITE);
    CloseHandle(hProc);
    DeleteFileA(path2);

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(STARTUPINFOA);
    PROCESS_INFORMATION pi = { 0 };
    CreateProcess(NULL, "notepad", NULL, NULL, TRUE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);
#endif
  }
    return ERR_SUCCESS;
  default:
    return ERR_FATAL;
  }

  if(execute.length() > 0)
  {
    if(!ExecuteProcess(execute.UnsafeString()))
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