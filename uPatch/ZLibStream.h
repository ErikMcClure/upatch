// Copyright ©2017 Black Sphere Studios

#ifndef __ZLIBSTREAM_H__UPATCH__
#define __ZLIBSTREAM_H__UPATCH__

#include "bss-util/stream.h"
#include "zlib.h"
#include <istream>
#include <ostream>

namespace upatch {
  struct InstallPayload;

  class ZLibStream : public bss::StreamBufFunction
  {
    inline ZLibStream(const ZLibStream& copy) BSS_DELETEFUNC
      inline ZLibStream& operator =(const ZLibStream& right) BSS_DELETEFUNCOP

  public:
    inline ZLibStream(ZLibStream&& mov) : StreamBufFunction(std::move(mov)) {}
    ZLibStream(std::istream& in, size_t bufsize = DEFAULTBUFSIZE);
    ZLibStream(std::ostream& out, int level = -1, size_t bufsize = DEFAULTBUFSIZE);
    ~ZLibStream();

  protected:
    virtual void _onwrite() override;
    virtual void _onread() override;

    char* _icur;
    char* _iend;
    z_stream strm;
  };
}

#endif