// Copyright ©2017 Black Sphere Studios

#ifndef __PATCHES_H__UPATCH__
#define __PATCHES_H__UPATCH__

#include "Payload.h"
#include <istream>
#include <ostream>

namespace upatch {
  ERROR_CODES DeltaCreate(std::istream& oldf, std::istream& newf, std::ostream& out, PATCH_TECH& tech, size_t& size, MD5HASH& hash);
  ERROR_CODES DeltaApply(std::istream& source, std::istream& data, size_t len, std::ostream& out, PATCH_TECH tech);

  ERROR_CODES bsdiffCreate(std::istream& oldf, std::istream& newf, std::ostream& out);
  ERROR_CODES bsdiffApply(std::istream& source, std::istream& data, size_t len, std::ostream& out);
  //ERROR_CODES zdeltaCreate(std::istream& oldf, std::istream& newf, std::ostream& out);
  //ERROR_CODES zdeltaApply(std::istream& source, std::istream& data, size_t len, std::ostream& out);
}

#endif