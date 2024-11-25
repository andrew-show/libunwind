//===------------------------------- unwind.h -----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//
// C++ ABI Level 1 ABI documented at:
//   https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html
//
//===----------------------------------------------------------------------===//

#ifndef __UNWIND_H__
#define __UNWIND_H__

#include <__libunwind_config.h>

#include <stdint.h>
#include <stddef.h>

typedef enum {
    _URC_NO_REASON = 0,
    _URC_OK = 0,
    _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
    _URC_FATAL_PHASE2_ERROR = 2,
    _URC_FATAL_PHASE1_ERROR = 3,
    _URC_NORMAL_STOP = 4,
    _URC_END_OF_STACK = 5,
    _URC_HANDLER_FOUND = 6,
    _URC_INSTALL_CONTEXT = 7,
    _URC_CONTINUE_UNWIND = 8,
} _Unwind_Reason_Code;

typedef enum {
    _UA_SEARCH_PHASE = 1,
    _UA_CLEANUP_PHASE = 2,
    _UA_HANDLER_FRAME = 4,
    _UA_FORCE_UNWIND = 8,
    _UA_END_OF_STACK = 16 // gcc extension to C++ ABI
} _Unwind_Action;

typedef struct _Unwind_Context _Unwind_Context;   // opaque

struct _Unwind_Context;   // opaque
struct _Unwind_Exception; // forward declaration
typedef struct _Unwind_Exception _Unwind_Exception;

struct _Unwind_Exception {
    uint64_t exception_class;
    void (*exception_cleanup)(_Unwind_Reason_Code reason,
                              _Unwind_Exception *exc);

    uintptr_t private_1; // non-zero means forced unwind
    uintptr_t private_2; // holds sp that phase1 found for phase2 to use

#if __SIZEOF_POINTER__ == 4
    // The implementation of _Unwind_Exception uses an attribute mode on the
    // above fields which has the side effect of causing this whole struct to
    // round up to 32 bytes in size (48 with SEH). To be more explicit, we add
    // pad fields added for binary compatibility.
    uint32_t reserved[3];
#endif
    // The Itanium ABI requires that _Unwind_Exception objects are "double-word
    // aligned".  GCC has interpreted this to mean "use the maximum useful
    // alignment for the target"; so do we.
} __attribute__((__aligned__));

typedef _Unwind_Reason_Code (*_Unwind_Stop_Fn)
(int version,
 _Unwind_Action actions,
 uint64_t exceptionClass,
 _Unwind_Exception* exceptionObject,
 struct _Unwind_Context* context,
 void* stop_parameter );

typedef _Unwind_Reason_Code (*_Unwind_Personality_Fn)(
    int version, _Unwind_Action actions, uint64_t exceptionClass,
    _Unwind_Exception *exceptionObject, struct _Unwind_Context *context);

#ifdef __cplusplus
extern "C" {
#endif

//
// The following are the base functions documented by the C++ ABI
//

extern _Unwind_Reason_Code
_Unwind_RaiseException(_Unwind_Exception *exception_object);
extern void _Unwind_Resume(_Unwind_Exception *exception_object);

extern void _Unwind_DeleteException(_Unwind_Exception *exception_object);

extern uintptr_t _Unwind_GetGR(struct _Unwind_Context *context, int index);
extern void _Unwind_SetGR(struct _Unwind_Context *context, int index,
                          uintptr_t new_value);
extern uintptr_t _Unwind_GetIP(struct _Unwind_Context *context);
extern void _Unwind_SetIP(struct _Unwind_Context *, uintptr_t new_value);

extern uintptr_t _Unwind_GetRegionStart(struct _Unwind_Context *context);
extern uintptr_t
_Unwind_GetLanguageSpecificData(struct _Unwind_Context *context);

extern _Unwind_Reason_Code
_Unwind_ForcedUnwind(_Unwind_Exception *exception_object,
                     _Unwind_Stop_Fn stop, void *stop_parameter);

//
// The following are semi-suppoted extensions to the C++ ABI
//

//
//  called by __cxa_rethrow().
//
extern _Unwind_Reason_Code
_Unwind_Resume_or_Rethrow(_Unwind_Exception *exception_object);

// _Unwind_Backtrace() is a gcc extension that walks the stack and calls the
// _Unwind_Trace_Fn once per frame until it reaches the bottom of the stack
// or the _Unwind_Trace_Fn function returns something other than _URC_NO_REASON.
typedef _Unwind_Reason_Code (*_Unwind_Trace_Fn)(struct _Unwind_Context *,
                                                void *);
extern _Unwind_Reason_Code _Unwind_Backtrace(_Unwind_Trace_Fn, void *);

// _Unwind_GetCFA is a gcc extension that can be called from within a
// personality handler to get the CFA (stack pointer before call) of
// current frame.
extern uintptr_t _Unwind_GetCFA(struct _Unwind_Context *);


// _Unwind_GetIPInfo is a gcc extension that can be called from within a
// personality handler.  Similar to _Unwind_GetIP() but also returns in
// *ipBefore a non-zero value if the instruction pointer is at or before the
// instruction causing the unwind. Normally, in a function call, the IP returned
// is the return address which is after the call instruction and may be past the
// end of the function containing the call instruction.
extern uintptr_t _Unwind_GetIPInfo(struct _Unwind_Context *context,
                                   int *ipBefore);


// _Unwind_Find_FDE() will locate the FDE if the pc is in some function that has
// an associated FDE. Note, Mac OS X 10.6 and later, introduces "compact unwind
// info" which the runtime uses in preference to DWARF unwind info.  This
// function will only work if the target function has an FDE but no compact
// unwind info.
struct dwarf_eh_bases {
    uintptr_t tbase;
    uintptr_t dbase;
    uintptr_t func;
};
extern const void *_Unwind_Find_FDE(const void *pc, struct dwarf_eh_bases *);


// This function attempts to find the start (address of first instruction) of
// a function given an address inside the function.  It only works if the
// function has an FDE (DWARF unwind info).
// This function is unimplemented on Mac OS X 10.6 and later.  Instead, use
// _Unwind_Find_FDE() and look at the dwarf_eh_bases.func result.
extern void *_Unwind_FindEnclosingFunction(void *pc);

// Mac OS X does not support text-rel and data-rel addressing so these functions
// are unimplemented
extern uintptr_t _Unwind_GetDataRelBase(struct _Unwind_Context *context);
extern uintptr_t _Unwind_GetTextRelBase(struct _Unwind_Context *context);

#ifdef __cplusplus
}
#endif

#endif // __UNWIND_H__
