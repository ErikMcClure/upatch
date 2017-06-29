// Copyright ©2017 Black Sphere Studios

#include "Source.h"
#include "Util.h"
#include "bss-util/JSON.h"
#include <sstream>
#include <fstream>

using namespace upatch;
using namespace bss;

Source::Hop Source::Hop::EMPTY = { {0,0,0,0},{ 0,0,0,0 } };

ERROR_CODES Source::Load(Source& src, const char* url, const char* file)
{
  if(!url)
    return ERR_INVALID_ARGUMENTS;
  std::fstream fs;
  std::stringstream ss(std::ios_base::out | std::ios_base::in | std::ios_base::binary);
  if(file)
    fs.open(file, std::ios_base::out | std::ios_base::in | std::ios_base::binary | std::ios_base::trunc);
  std::iostream& target = fs.good() ? static_cast<std::iostream&>(fs) : static_cast<std::iostream&>(ss);
  MD5HASH hash;
  ERROR_CODES r = DownloadFile(url, target, hash, 0, 0);
  if(r != ERR_SUCCESS)
    return ToControlError(r);

  std::stringstream md5ss(std::ios_base::out | std::ios_base::in | std::ios_base::binary);
  MD5HASH ignore;
  r = DownloadFile(url + Str(".md5"), md5ss, ignore, 0, 0);
  if(r == ERR_SUCCESS)
  {
    if(ConvertMD5(md5ss.str().c_str(), ignore))
      if(!CompareMD5(hash, ignore, "Source"))
        return ERR_DOWNLOAD_CORRUPT;
  }

  try
  {
    ParseJSON<Source>(src, target);
  }
  catch(std::runtime_error e)
  {
    return ERR_INVALID_CONTROL_FILE;
  }
  return ERR_SUCCESS;
}