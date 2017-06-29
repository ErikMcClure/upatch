// Copyright ©2017 Black Sphere Studios

#include "Util.h"
#include "Options.h"
#include "Payload.h"
#include "Patches.h"
#include "os.h"
#include "bss-util/Str.h"
#include "bss-util/algo.h"
#include "bss-util/stream.h"
#include "bss-util/os.h"
#include "zlib.h"
#include "md5.h"
#include "curl/curl.h"
#include <iostream>
#include <fstream>

using namespace upatch;
using namespace bss;

struct DLStream
{
  std::ostream& out;
  MD5_CTX& md5;
};

size_t curl_write_stream(char *ptr, size_t size, size_t nmemb, void* userdata)
{
  DLStream* s = reinterpret_cast<DLStream*>(userdata);
  MD5_Update(&s->md5, ptr, size*nmemb);
  s->out.write(ptr, size*nmemb);
  return size*nmemb;
}

ERROR_CODES upatch::DownloadFile(const char* url, std::ostream& s, uint8_t(&md5hash)[16], curl_xferinfo_callback callback, void* callbackdata)
{
  CURL* curl = curl_easy_init();
  if(!curl) return ERR_CURL_FAILURE;
  MD5_CTX ctx;
  MD5_Init(&ctx);
  z_stream zstream = { 0 };

  DLStream stream = { s, ctx };
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, !callback?0:1);
  if(callback) curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, callback);
  if(callback) curl_easy_setopt(curl, CURLOPT_XFERINFODATA, callbackdata);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_stream);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &stream);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);

  ERROR_CODES r = ERR_SUCCESS;
  CURLcode code = curl_easy_perform(curl);
  switch(code)
  {
  case CURLE_OK:
    break;
  case CURLE_COULDNT_CONNECT:
  case CURLE_COULDNT_RESOLVE_HOST:
  case CURLE_COULDNT_RESOLVE_PROXY:
  case CURLE_URL_MALFORMAT:
  case CURLE_TFTP_NOTFOUND:
  case CURLE_REMOTE_FILE_NOT_FOUND:
    r = ERR_DOWNLOAD_NOT_FOUND;
    break;
  case CURLE_LOGIN_DENIED:
  case CURLE_FILE_COULDNT_READ_FILE:
  case CURLE_FTP_WEIRD_SERVER_REPLY:
  case CURLE_REMOTE_ACCESS_DENIED:
  case CURLE_FTP_WEIRD_PASS_REPLY:
    r = ERR_DOWNLOAD_ACCESS_DENIED;
    break;
  case CURLE_FILESIZE_EXCEEDED:
  case CURLE_FTP_COULDNT_RETR_FILE:
  case CURLE_OUT_OF_MEMORY:
    r = ERR_DOWNLOAD_INTERRUPTED;
    break;
  case CURLE_PARTIAL_FILE:
    r = ERR_DOWNLOAD_CORRUPT;
    break;
  default:
    r = ERR_CURL_FAILURE;
    break;
  }
  if(code != CURLE_OK)
    UPLOG(2, "CURL error: ", code);

  curl_easy_cleanup(curl);
  MD5_Final(md5hash, &ctx);
  return r;
}

ERROR_CODES upatch::DownloadHop(const Source::Hop& hop, std::ostream& s, int(*callback)(void*, long long, long long, long long, long long), void* callbackdata)
{
  MD5HASH hash;
  ERROR_CODES err = ERR_NO_VALID_MIRRORS;
  for(auto& mirror : hop.mirrors)
  {
    if((err = DownloadFile(mirror.c_str(), s, hash, callback, callbackdata)) == ERR_SUCCESS)
      break;
  }
  if(err != ERR_SUCCESS)
    return ERR_NO_VALID_MIRRORS;
  MD5HASH hophash;
  ConvertMD5(hop.md5.c_str(), hophash);
  if(!CompareMD5(hophash, hash, "Downloaded file"))
    return ERR_DOWNLOAD_CORRUPT;
  return ERR_SUCCESS;
}

ERROR_CODES upatch::ToControlError(ERROR_CODES err)
{
  switch(err)
  {
  case ERR_DOWNLOAD_NOT_FOUND: return ERR_CANT_FIND_CONTROL_FILE;
  case ERR_DOWNLOAD_ACCESS_DENIED: return ERR_CANT_DOWNLOAD_CONTROL_FILE;
  case ERR_DOWNLOAD_CORRUPT: return ERR_INVALID_CONTROL_FILE;
  }
  return err;
}

const static int CHUNK = (1 << 18);
char upatch::PackZip(std::istream& in, std::ostream& out, char level)
{
  int ret, flush;
  unsigned have;
  z_stream strm;
  unsigned char bufin[CHUNK];
  unsigned char bufout[CHUNK];

  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  ret = deflateInit(&strm, level);
  if(ret != Z_OK)
    return ret;

  do {
    in.read((char*)bufin, CHUNK);
    strm.avail_in = in.gcount();
    if(in.bad()) {
      (void)deflateEnd(&strm);
      return Z_ERRNO;
    }
    flush = in.eof() ? Z_FINISH : Z_NO_FLUSH;
    strm.next_in = bufin;
    do
    {
      strm.avail_out = CHUNK;
      strm.next_out = bufout;
      ret = deflate(&strm, flush);    // no bad return value
      assert(ret != Z_STREAM_ERROR);  // state not clobbered
      have = CHUNK - strm.avail_out;
      out.write((char*)bufout, have);
      if(out.bad()) {
        (void)deflateEnd(&strm);
        return Z_ERRNO;
      }
    } while(strm.avail_out == 0);
    assert(strm.avail_in == 0); // ensure all input was used
  } while(flush != Z_FINISH);
  assert(ret == Z_STREAM_END);

  (void)deflateEnd(&strm);
  return ERR_SUCCESS;
}

char upatch::UnpackZip(std::istream& in, std::ostream& out)
{
  int ret;
  unsigned have;
  z_stream strm;
  unsigned char bin[CHUNK];
  unsigned char bout[CHUNK];

  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;
  ret = inflateInit(&strm);
  if(ret != Z_OK)
    return ret;

  do {
    in.read((char*)bin, CHUNK);
    strm.avail_in = in.gcount();
    if(in.bad()) {
      (void)inflateEnd(&strm);
      return Z_ERRNO;
    }
    if(strm.avail_in == 0)
      break;
    strm.next_in = bin;

    do {
      strm.avail_out = CHUNK;
      strm.next_out = bout;

      ret = inflate(&strm, Z_NO_FLUSH);
      assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
      switch(ret) {
      case Z_NEED_DICT:
        ret = Z_DATA_ERROR;     /* and fall through */
      case Z_DATA_ERROR:
      case Z_MEM_ERROR:
        (void)inflateEnd(&strm);
        return ret;
      }

      have = CHUNK - strm.avail_out;
      out.write((const char*)bout, have);
      if(out.bad()) {
        (void)inflateEnd(&strm);
        return Z_ERRNO;
      }
    } while(strm.avail_out == 0);
  } while(ret != Z_STREAM_END);
  (void)inflateEnd(&strm);
  return ret == Z_STREAM_END ? ERR_SUCCESS : ERR_FATAL;
}

size_t upatch::CalcMD5(std::istream& in, uint8_t(&out)[16])
{
  static const int CHUNK = 16384;
  MD5_CTX ctx;
  MD5_Init(&ctx);
  char bytes[CHUNK];
  size_t size = 0;

  do
  {
    in.read(bytes, CHUNK);
    size += in.gcount();
    MD5_Update(&ctx, bytes, in.gcount());
  } while(!!in && !in.eof() && in.peek() != -1);

  MD5_Final(out, &ctx);
  return size;
}

bool upatch::CheckWritePermission(const char* file)
{
  std::fstream f(file, std::ios_base::out | std::ios_base::binary);
  if(!f)
  {
    UPLOG(2, "Do not have write access to ", file);
    return false;
  }
  f.close();
  return true;
}

bool upatch::ConvertMD5(const char* in, uint8_t(&out)[16])
{
  size_t len = strlen(in);
  if(Base64Decode(in, len, 0) != 16)
    return false;

  Base64Decode(in, len, out);
  return true;
}

Str upatch::ConvertMD5(const uint8_t(&in)[16])
{
  Str out;
  out.resize(Base64Encode(in, 16, 0));
  Base64Encode(in, 16, out.UnsafeString());
  return out;
}

bool upatch::CompareMD5(uint8_t(&l)[16], uint8_t(&r)[16], const char* debugname)
{
  if(!memcmp(l, r, 16))
    return true;
  if(debugname)
    UPLOG(2, debugname, " hash [", ConvertMD5(l), "] does not match expected hash [", ConvertMD5(r), "]");
  return false;
}

typedef std::pair<bssVersionInfo, const Source::Hop*> HopPair;

void r_find_hops(bssVersionInfo v, const Source::Hop& h, std::vector<HopPair>& edges, std::vector<Source::Hop>& out)
{
  if(h.mirrors.empty()) return; // If we have no valid mirrors this whole chain is invalid
  auto iter = std::lower_bound(edges.begin(), edges.end(), v, [](HopPair& a, bssVersionInfo b) -> bool { return b.version < a.first.version; });

  for(; !iter->first.version == v.version; ++iter)
  {
    r_find_hops(iter->second->to, *iter->second, edges, out);
    if(!out.empty())
    {
      out.push_back(h);
      return;
    }
  }
}

void upatch::FindHops(bssVersionInfo version, const Source& src, std::vector<Source::Hop>& out)
{
  if(version.version >= src.latest.version)
    return; // There's nothing to update!

  std::vector<HopPair> bases; // List of base versions. We start with our version, then work down the list of available full updates.
  std::vector<HopPair> edges; // list of version hops in [from, hop*] form.

  for(const Source::Hop& h : src.hops)
  {
    if(!h.from.version)
      bases.push_back(HopPair(h.to, &h));
    else
      bases.push_back(HopPair(h.from, &h));
  }

  std::sort(bases.begin(), bases.end(), [](HopPair& a, HopPair& b) { return b.first.version < a.first.version; });
  std::sort(edges.begin(), edges.end(), [](HopPair& a, HopPair& b) { char r = SGNCOMPARE(b.first.version, a.first.version); return !r ? SGNCOMPARE(b.first.version, a.first.version) : r; });
  bases.insert(bases.begin(), HopPair(version, &Source::Hop::EMPTY)); // insert current version before sorted elements

  for(HopPair& pair : bases)
  {
    r_find_hops(pair.first, *pair.second, edges, out);
    if(!out.empty())
      break;
  }

  std::reverse(out.data(), out.data() + out.size());
}

ERROR_CODES upatch::CreatePatch(const char* from, const char* to, const char* reg, upatch::Payload& payload, std::ostream& out)
{
  assert(from);
  std::vector<Str> fromfiles;
  std::vector<Str> tofiles;
  ListDir(from, fromfiles, 1);
  if(to)
    ListDir(to, tofiles, 1);
  auto fn = [](const Str& l, const Str& r) -> bool { return strcmp(l, r) < 0; };
  std::sort(fromfiles.begin(), fromfiles.end(), fn);
  std::sort(tofiles.begin(), tofiles.end(), fn);

  while(fromfiles.size() || tofiles.size())
  {
    if(!fromfiles.size() || fn(fromfiles.back(), tofiles.back()))
    {
      BinaryPayloadAdd add = { tofiles.back() };
      std::ifstream fs(to + tofiles.back(), std::ios_base::in | std::ios_base::binary);
      add.data = CalcMD5(fs, add.self);
      fs.close();
      add.absolute = false;
      payload.update.push_back(PayloadPack(add));
      tofiles.pop_back();
      continue;
    }

    if(!tofiles.size() || fn(tofiles.back(), fromfiles.back()))
    {
      BinaryPayloadRemove rm = { fromfiles.back() };
      std::ifstream fs(from + fromfiles.back(), std::ios_base::in | std::ios_base::binary);
      CalcMD5(fs, rm.target);
      rm.absolute = false;
      payload.update.push_back(PayloadPack(rm));
      fromfiles.pop_back();
      continue;
    }

    assert(!strcmp(tofiles.back(), fromfiles.back()));
    BinaryPayloadDelta delta;
    delta.file.path = tofiles.back();
    delta.file.absolute = false;
    
    std::ifstream tfs(to + tofiles.back(), std::ios_base::in | std::ios_base::binary);
    CalcMD5(tfs, delta.result);
    std::ifstream ffs(from + fromfiles.back(), std::ios_base::in | std::ios_base::binary);
    CalcMD5(ffs, delta.target);
    std::ofstream dfs(to + tofiles.back() + Options::DELTA_EXT_NAME, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);

    delta.patch = PATCH_DEFAULT;
    DeltaCreate(ffs, tfs, dfs, delta.patch, delta.file.data, delta.file.self);
    tfs.close();
    ffs.close();
    dfs.close();
    payload.update.push_back(PayloadPack(delta));
  }
  if(reg != 0)
  {
    std::ifstream fs(reg, std::ios_base::in | std::ios_base::binary);
    ParseReg(fs, payload.update);
  }

  // Write out finalized payload metadata
  out.write((char*)&payload, sizeof(Payload));

  const int CHUNK = (1 << 18);
  char buf[CHUNK];

  // Generate and write out finalized payload data block
  for(auto& p : payload.update)
  {
    switch(p.tag())
    {
    case PayloadPack::Type<BinaryPayloadAdd>::value:
    {
      std::ifstream fs(p.get<BinaryPayloadAdd>().path, std::ios_base::in | std::ios_base::binary);
      size_t expected = p.get<BinaryPayloadAdd>().data;
      while(expected)
      {
        fs.read(buf, CHUNK);
        expected -= fs.gcount();
        out.write(buf, fs.gcount());
      }
      if(fs.get() != std::char_traits<char>::eof())
      {
        UPLOG(1, "Delta pack generation aborted because file was not expected length of ", p.get<BinaryPayloadAdd>().data);
        return ERR_FATAL;
      }
      fs.close();
    }
    break;
    case PayloadPack::Type<BinaryPayloadDelta>::value:
    {
      Str file = to + p.get<BinaryPayloadDelta>().file.path + Options::DELTA_EXT_NAME;
      std::ifstream fs(file, std::ios_base::in | std::ios_base::binary);
      size_t expected = p.get<BinaryPayloadDelta>().file.data;
      while(expected)
      {
        fs.read(buf, CHUNK);
        expected -= fs.gcount();
        out.write(buf, fs.gcount());
      }
      if(fs.get() != std::char_traits<char>::eof())
      {
        UPLOG(1, "Delta pack generation aborted because file was not expected length of ", p.get<BinaryPayloadDelta>().file.data);
        return ERR_FATAL;
      }
      fs.close();
      std::remove(file); // delete temporary delta file
    }
    break;
    }
  }

  return ERR_SUCCESS;
}
ERROR_CODES upatch::CreatePatchGit(const char* commitfrom, const char* curcommit, const char* reg, upatch::Payload& payload, std::ostream& out)
{
  return ERR_FATAL;
  // If curcommit is NULL, simply use HEAD

  // Looks up which files changed between the old and the new commits


  // Switches the entire branch to the old commit, then copies all those files to a temporary folder


  // Switches entire branch to the new commit (or HEAD)


  // Now creates a patch using the temporary folder as the from directory




  // Deletes the temporary folder
}

Str upatch::GetCurrentDir()
{
  Str curdir = GetCurrentPath();
  if(char* p = strrchr(curdir.UnsafeString(), L'/'))
    p[1] = 0;
  if(char* p = strrchr(curdir.UnsafeString(), L'\\'))
    p[1] = 0;
  assert(curdir.back() == '/' || curdir.back() == '\\');
  return curdir;
}

Str upatch::GetCurrentName()
{
  Str curdir = GetCurrentPath();
  if(char* p = strrchr(curdir.UnsafeString(), L'/'))
    return Str(p + 1);
  if(char* p = strrchr(curdir.UnsafeString(), L'\\'))
    return Str(p + 1);
  return curdir;
}

ERROR_CODES upatch::ParseReg(std::istream& file, std::vector<PayloadPack>& pack)
{
  return ERR_FATAL;
}
