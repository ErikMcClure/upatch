// Copyright ©2017 Black Sphere Studios

#include "Patches.h"
#include "md5.h"
using namespace upatch;

ERROR_CODES upatch::DeltaCreate(std::istream& oldf, std::istream& newf, std::ostream& out, PATCH_TECH& tech, size_t& size, MD5HASH& hash)
{
  switch(tech)
  {
  case PATCH_ZDELTA:
    return ERR_FATAL;
  case PATCH_BSDIFF:
    return bsdiffCreate(oldf, newf, out);
  default:
    tech = PATCH_NONE;
  case PATCH_NONE:
    break;
  }

  MD5_CTX ctx;
  MD5_Init(&ctx);
  size = 0;
  static const int BUFSIZE = 1 << 18;
  char buf[BUFSIZE];
  while(newf)
  {
    newf.read(buf, BUFSIZE);
    size += newf.gcount();
    MD5_Update(&ctx, buf, newf.gcount());
    out.write(buf, newf.gcount());
  }

  MD5_Final(hash, &ctx);
  return ERR_SUCCESS;
}
ERROR_CODES upatch::DeltaApply(std::istream& source, std::istream& data, size_t len, std::ostream& out, PATCH_TECH tech)
{
  switch(tech)
  {
  case PATCH_ZDELTA:
    return ERR_FATAL;
  case PATCH_BSDIFF:
    return bsdiffApply(source, data, len, out);
  default:
  case PATCH_NONE:
    break;
  }

  static const int BUFSIZE = 1 << 18;
  char buf[BUFSIZE];
  while(data && len > 0)
  {
    data.read(buf, BUFSIZE);
    len -= data.gcount();
    out.write(buf, data.gcount());
  }

  return ERR_SUCCESS;
}

ERROR_CODES upatch::bsdiffCreate(std::istream& oldf, std::istream& newf, std::ostream& out)
{
  return ERR_FATAL;
}
ERROR_CODES upatch::bsdiffApply(std::istream& source, std::istream& data, size_t len, std::ostream& out)
{
  return ERR_FATAL;
}

/*
char zdeltaPatchCreate(std::istream& ofile, std::istream& nfile, std::ostream& out)
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

  // init huffman coder
  rval = zd_deflateInit(&s, ZD_DEFAULT_COMPRESSION);
  if(rval != ZD_OK)
  {
    fprintf(stderr, "%s error: %d\n", "deflateInit", rval);
    return rval;
  }

  // compress the data
  while((rval = zd_deflate(&s, ZD_FINISH)) == ZD_OK)
  {
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

  if(rval != ZD_STREAM_END)
  {
    fprintf(stderr, "%s error: %d\n", "deflateInit", rval);
    zd_deflateEnd(&s);
    return rval;
  }

  return zd_deflateEnd(&s);
}

char zdeltaPatchApply(std::istream& delta, std::istream& file, std::ostream& out)
{

}*/
