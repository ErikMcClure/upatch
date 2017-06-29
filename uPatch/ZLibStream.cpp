// Copyright ©2017 Black Sphere Studios

#include "ZLibStream.h"
#include "Options.h"

using namespace upatch;

ZLibStream::ZLibStream(std::istream& in, size_t bufsize) : bss::StreamBufFunction(in, bufsize)
{
  bss::bssFill(strm, 0);
  if(int ret = inflateInit(&strm))
  {
    UPLOG(1, "zlib inflateInit failed with error ", ret);
    setg(0, 0, 0);
  }
  _icur = _iend = _ibuf;
}
ZLibStream::ZLibStream(std::ostream& out, int level, size_t bufsize) : bss::StreamBufFunction(out, bufsize)
{
  bss::bssFill(strm, 0);
  if(int ret = deflateInit(&strm, level))
  {
    UPLOG(1, "zlib deflateInit failed with error ", ret);
    setp(0, 0, 0);
  }
  _icur = _iend = _ibuf;
}
ZLibStream::~ZLibStream()
{
  if(_in)
    inflateEnd(&strm);
  if(_out)
    deflateEnd(&strm);
}
void ZLibStream::_onwrite()
{
  if(!strm.avail_out)
  {
    assert(strm.avail_in == 0); // ensure all input was used
    _in->read(_ibuf, _sz);
    strm.avail_in = _in->gcount();
  }
  if(_in->bad())
  {
    UPLOG(1, "zlib _in stream in bad state");
    return;
  }
  strm.next_in = (Bytef*)_ibuf;
  do
  {
    strm.avail_out = _sz;
    strm.next_out = (Bytef*)_obuf;
    int ret = deflate(&strm, _in->eof() ? Z_FINISH : Z_NO_FLUSH);    // no bad return value
    assert(ret != Z_STREAM_ERROR);  // state not clobbered
    std::streamsize have = _sz - strm.avail_out;
    _out->write(_obuf, have);
    if(_out->bad())
    {
      UPLOG(1, "zlib _out stream in bad state");
      return;
    }
  } while(strm.avail_out == 0);
}
void ZLibStream::_onread()
{
  // pointers for free region in output buffer
  char * _outbuf_free_start = _obuf;
  do
  {
    // read more input if none available
    if(_icur == _iend)
    {
      // empty input buffer: refill from the start
      _icur = _ibuf;
      _in->read(_ibuf, _sz);
      std::streamsize sz = _in->gcount();
      _iend = _ibuf + sz;
      if(_iend == _icur)
        break; // end of input
    }
    // run inflate() on input
    strm.next_in = reinterpret_cast<Bytef*>(_icur);
    strm.avail_in = _iend - _icur;
    strm.next_out = reinterpret_cast<Bytef*>(_outbuf_free_start);
    strm.avail_out = (_obuf + _sz) - _outbuf_free_start;
    int ret = inflate(&strm, Z_NO_FLUSH);
    // process return code
    if(ret != Z_OK && ret != Z_STREAM_END)
    {
      this->setg(0, 0, 0);
      UPLOG(1, "zlib threw error while deflating: ", ret);
      break;
    }
    // update in&out pointers following inflate()
    _icur = reinterpret_cast< decltype(_icur) >(strm.next_in);
    _iend = _icur + strm.avail_in;
    _outbuf_free_start = reinterpret_cast<char*>(strm.next_out);
    assert(_outbuf_free_start + strm.avail_out == _obuf + _sz);
  } while(_outbuf_free_start == _obuf);

  this->setg(_obuf, _obuf, _outbuf_free_start);
}