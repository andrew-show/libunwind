//===------------------------- __libunwind_config.h -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef ____LIBUNWIND_CONFIG_H__
#define ____LIBUNWIND_CONFIG_H__

#if defined(__i386__)
#  define _LIBUNWIND_CONTEXT_SIZE 8
#  define _LIBUNWIND_CURSOR_SIZE 127
#elif defined(__x86_64__)
#  define _LIBUNWIND_CONTEXT_SIZE 21
#  define _LIBUNWIND_CURSOR_SIZE 127
#elif defined(__powerpc64__)
#  define _LIBUNWIND_CONTEXT_SIZE 168
#  define _LIBUNWIND_CURSOR_SIZE 255
#elif defined(__ppc__)
#  define _LIBUNWIND_CONTEXT_SIZE 117
#  define _LIBUNWIND_CURSOR_SIZE 124
#elif defined(__aarch64__)
#  define _LIBUNWIND_CONTEXT_SIZE 66
#  define _LIBUNWIND_CURSOR_SIZE 213
#elif defined(__arm__)
#  if defined(__ARM_WMMX)
#    define _LIBUNWIND_CONTEXT_SIZE 61
#    define _LIBUNWIND_CURSOR_SIZE 68
#  else
#    define _LIBUNWIND_CONTEXT_SIZE 42
#    define _LIBUNWIND_CURSOR_SIZE 49
#  endif
#elif defined(__or1k__)
#  define _LIBUNWIND_CONTEXT_SIZE 16
#  define _LIBUNWIND_CURSOR_SIZE 24
#elif defined(__hexagon__)
// Values here change when : Registers.hpp - hexagon_thread_state_t change
#  define _LIBUNWIND_CONTEXT_SIZE 18
#  define _LIBUNWIND_CURSOR_SIZE 24
#elif defined(__mips__)
#  if defined(_ABIO32) && _MIPS_SIM == _ABIO32
#    if defined(__mips_hard_float)
#      define _LIBUNWIND_CONTEXT_SIZE 50
#      define _LIBUNWIND_CURSOR_SIZE 57
#    else
#      define _LIBUNWIND_CONTEXT_SIZE 18
#      define _LIBUNWIND_CURSOR_SIZE 24
#    endif
#  elif defined(_ABIN32) && _MIPS_SIM == _ABIN32
#    if defined(__mips_hard_float)
#      define _LIBUNWIND_CONTEXT_SIZE 67
#      define _LIBUNWIND_CURSOR_SIZE 74
#    else
#      define _LIBUNWIND_CONTEXT_SIZE 35
#      define _LIBUNWIND_CURSOR_SIZE 42
#    endif
#  elif defined(_ABI64) && _MIPS_SIM == _ABI64
#    if defined(__mips_hard_float)
#      define _LIBUNWIND_CONTEXT_SIZE 67
#      define _LIBUNWIND_CURSOR_SIZE 79
#    else
#      define _LIBUNWIND_CONTEXT_SIZE 35
#      define _LIBUNWIND_CURSOR_SIZE 47
#    endif
#  else
#    error "Unsupported MIPS ABI and/or environment"
#  endif
#elif defined(__sparc__)
#  define _LIBUNWIND_CONTEXT_SIZE 16
#  define _LIBUNWIND_CURSOR_SIZE 23
#elif defined(__riscv)
#  if __riscv_xlen == 64
#    define _LIBUNWIND_CONTEXT_SIZE 64
#    define _LIBUNWIND_CURSOR_SIZE 76
#  else
#    error "Unsupported RISC-V ABI"
#  endif
#elif defined(__ve__)
#  define _LIBUNWIND_CONTEXT_SIZE 67
#  define _LIBUNWIND_CURSOR_SIZE 79
#else
#  error "Unsupported architecture."
#endif

#endif // ____LIBUNWIND_CONFIG_H__
