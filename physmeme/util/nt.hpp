#pragma once
#ifndef _NT_HPP_
#define _NT_HPP_

#define WIN32_LEAN_AND_MEAN
#include <ntdef.h>
#include <ntifs.h>

// Prevent redefinition of inline functions from wdm.h
#ifndef _WDM_H_
#define _WDM_H_
#endif

typedef struct _PiDDBCacheEntry
{
    LIST_ENTRY list;
    UNICODE_STRING driver_name;
    ULONG time_stamp;
} PiDDBCacheEntry;

typedef struct _PIDCacheobj
{
    LIST_ENTRY list;
} PIDCacheobj;

#endif // _NT_HPP_