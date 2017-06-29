// Copyright ©2017 Black Sphere Studios

#ifndef __VERSION_H__UPATCH__
#define __VERSION_H__UPATCH__

#define UPATCH_VERSION_MAJOR 0
#define UPATCH_VERSION_MINOR 1
#define UPATCH_VERSION_REVISION 0

#ifdef uPatch_EXPORTS 
#pragma warning(disable:4251)
#define UPATCH_EXTERN extern BSS_COMPILER_DLLEXPORT
#else
#ifndef UPATCH_STATIC_LIB
#define UPATCH_EXTERN extern BSS_COMPILER_DLLIMPORT
#else
#define UPATCH_EXTERN extern
#endif
#endif

#endif
