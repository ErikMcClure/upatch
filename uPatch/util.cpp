#include "upatch.h"
#include "bss-util/cStr.h"
#include "zlib/zlib.h"
#include "md5.h"
#include "zdelta-2.1\zdlib.h"
#include <iostream>
#include <fstream>

bool DeleteSelf()
{
#ifdef BSS_PLATFORM_WIN32
  char buf[2048];
  GetModuleFileNameA(0, buf, 2048);
  CopyFileA(buf, TEMP_EXE_PATH, FALSE);
  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;

  HANDLE hFile = CreateFileA(TEMP_EXE_PATH, 0, FILE_SHARE_READ | FILE_SHARE_DELETE, &sa, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, 0);
  cStr cmd = cStrF("\"%s\" -x %i \"%s\"", TEMP_EXE_PATH, GetCurrentProcessId(), buf);
  STARTUPINFOA startinfo = { 0 };
  startinfo.cb = sizeof(STARTUPINFOA);
  PROCESS_INFORMATION procinfo = { 0 };
  if(!CreateProcessA(TEMP_EXE_PATH, cmd.UnsafeString(), 0, 0, TRUE, NORMAL_PRIORITY_CLASS, 0, 0, &startinfo, &procinfo))
  {
    std::cout << "FAILURE: Could not start temporary file!";
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

bool ExecuteProcess(char* str)
{
#ifdef BSS_PLATFORM_WIN32
  STARTUPINFOA si = { 0 };
  si.cb = sizeof(STARTUPINFOA);
  PROCESS_INFORMATION pi = { 0 };
  if(!CreateProcessA(0, str, 0, 0, FALSE, NORMAL_PRIORITY_CLASS, 0, 0, &si, &pi))
  {
    std::cout << "FAILURE: Could not execute " << str << std::endl;
    return false;
  }
#endif
  return true;
}

size_t curl_write_stream(char *ptr, size_t size, size_t nmemb, void* userdata)
{
  ((std::ostream*)userdata)->write(ptr, size*nmemb);
  return size*nmemb;
}

char DownloadFile(const char* url, std::ostream& s, curl_progress_callback* callback, void* data)
{
  CURL* curl = curl_easy_init();
  if(!curl) return ERR_CURL_FAILURE;
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, !callback?0:1);
  if(callback) curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, callback);
  if(callback) curl_easy_setopt(curl, CURLOPT_XFERINFODATA, data);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_stream);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

  char r = ERR_SUCCESS;
  switch(curl_easy_perform(curl))
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
  case CURLE_PARTIAL_FILE:
  case CURLE_FILESIZE_EXCEEDED:
  case CURLE_FTP_COULDNT_RETR_FILE:
  case CURLE_OUT_OF_MEMORY:
    r = ERR_DOWNLOAD_INTERRUPTED;
    break;
  default: r = ERR_CURL_FAILURE;
  }

  curl_easy_cleanup(curl);
  return r;
}

char _cmpver(const int* o, const int* n)
{
  char r = 0;
  for(int i = 0; i < 4; ++i)
    r = !r ? ((n[i] > o[i]) - (n[i] < o[i])) : r;
  return r;
}
char cmpver(const std::array<int, 4>& o, const std::array<int, 4>& n) { return _cmpver(o.data(), n.data()); }
char cmpver(const int(&o)[4], const int(&n)[4]) { return _cmpver(o, n); }


char ToControlError(char err)
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
char packzip(std::istream& in, std::ostream& out, char level)
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

char unpackzip(std::istream& in, std::ostream& out)
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

void calcmd5(std::istream& in, unsigned char(&out)[16])
{
  static const int CHUNK = 16384;
  MD5_CTX ctx;
  MD5_Init(&ctx);
  char bytes[CHUNK];

  do
  {
    in.read(bytes, CHUNK);
    MD5_Update(&ctx, bytes, in.gcount());
  } while(!!in && !in.eof() && in.peek() != -1);

  MD5_Final(out, &ctx);
}

bool CheckWritePermission(const char* file)
{
  std::fstream f(file, std::ios_base::out | std::ios_base::binary);
  if(!f)
  {
    std::cout << "ERROR: Do not have write permissions to " << file << std::endl;
    return false;
  }
  f.close();
  return true;
}

char packdelta(std::istream& ofile, std::istream& nfile, std::ostream& out)
{
  //static const int BUFFER_SIZE = 0b10000000000000000000;
  static const int BUFFER_SIZE = 512;

  char refbuf[BUFFER_SIZE];
  char targetbuf[BUFFER_SIZE];
  char outbuf[BUFFER_SIZE];
  int rval;
  zd_stream s;
  
  s.base[0] = (Bytef*)refbuf;
  s.base_avail[0] = BUFFER_SIZE;
  s.base_out[0] = 0;
  s.refnum = 1;

  s.next_in = (Bytef*)targetbuf;
  s.total_in = 0;
  s.avail_in = BUFFER_SIZE;

  s.next_out = (Bytef*)outbuf;
  s.total_out = 0;
  s.avail_out = BUFFER_SIZE;

  s.zalloc = (alloc_func)0;
  s.zfree = (free_func)0;
  s.opaque = (voidpf)0;

  ofile.read(refbuf, BUFFER_SIZE);
  nfile.read(targetbuf, BUFFER_SIZE);

  /* init huffman coder */
  rval = zd_deflateInit(&s, ZD_DEFAULT_COMPRESSION);
  if(rval != ZD_OK)
  {
    fprintf(stderr, "%s error: %d\n", "deflateInit", rval);
    return rval;
  }

  /* compress the data */
  while((rval = zd_deflate(&s, ZD_FINISH)) == ZD_OK) {
    ofile.read(refbuf, BUFFER_SIZE);
    s.base[0] = (Bytef*)refbuf;
    s.base_avail[0] = BUFFER_SIZE;

    nfile.read(targetbuf, BUFFER_SIZE);
    s.next_in = (Bytef*)targetbuf;
    s.avail_in = BUFFER_SIZE;

    out.write(outbuf, BUFFER_SIZE - s.avail_out);
    s.next_out = (Bytef*)outbuf;
    s.avail_out = BUFFER_SIZE;
  }

  out.write(outbuf, BUFFER_SIZE - s.avail_out);

  if(rval != ZD_STREAM_END) {
    fprintf(stderr, "%s error: %d\n", "deflateInit", rval);
    zd_deflateEnd(&s);
    return rval;
  }

  return zd_deflateEnd(&s);
}

char applydelta(std::istream& delta, std::istream& file, std::ostream& out)
{

}