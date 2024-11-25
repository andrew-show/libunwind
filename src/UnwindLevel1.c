//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//
// Implements C++ ABI Exception Handling Level 1 as documented at:
//      https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html
// using libunwind
//
//===----------------------------------------------------------------------===//

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <libunwind.h>
#include "unwind.h"

static _Unwind_Reason_Code
unwind_phase1(unw_context_t *uc, unw_cursor_t *cursor, _Unwind_Exception *exception_object)
{
    unw_init_local(cursor, uc);

    // Walk each frame looking for a place to stop.
    for ( ; ; ) {
        // Ask libunwind to get next frame (skip over first which is
        // _Unwind_RaiseException).
        int rc = unw_step(cursor);
        if (rc == 0)
            return _URC_END_OF_STACK;
        else if (rc < 0)
            return _URC_FATAL_PHASE1_ERROR;

        // See if frame has code to run (has personality routine).
        unw_proc_info_t frame;
        if (unw_get_proc_info(cursor, &frame) != UNW_ESUCCESS)
            return _URC_FATAL_PHASE1_ERROR;

        // If there is a personality routine, ask it if it will want to stop at
        // this frame.
        if (frame.handler != 0) {
            _Unwind_Personality_Fn personality = (_Unwind_Personality_Fn)frame.handler;
            _Unwind_Reason_Code reason = (*personality)(1,
                                                        _UA_SEARCH_PHASE,
                                                        exception_object->exception_class,
                                                        exception_object,
                                                        (struct _Unwind_Context *)(cursor));
            switch (reason) {
                case _URC_HANDLER_FOUND: {
                    // found a catch clause or locals that need destructing in this frame
                    // stop search and remember stack pointer at the frame
                    unw_word_t sp;
                    unw_get_reg(cursor, UNW_REG_SP, &sp);
                    exception_object->private_2 = (uintptr_t)sp;
                    return _URC_NO_REASON;
                }
                case _URC_CONTINUE_UNWIND:
                    // continue unwinding
                    break;
                default:
                    // something went wrong
                    return _URC_FATAL_PHASE1_ERROR;
            }
        }
    }

    return _URC_NO_REASON;
}


static _Unwind_Reason_Code
unwind_phase2(unw_context_t *uc, unw_cursor_t *cursor, _Unwind_Exception *exception_object)
{
    unw_init_local(cursor, uc);

    // uc is initialized by unw_getcontext in the parent frame. The first stack
    // frame walked is unwind_phase2.

    // Walk each frame until we reach where search phase said to stop.
    for ( ; ; ) {
        // Ask libunwind to get next frame (skip over first which is
        // _Unwind_RaiseException).
        int rc = unw_step(cursor);
        if (rc == 0)
            return _URC_END_OF_STACK;
        else if (rc < 0)
            return _URC_FATAL_PHASE2_ERROR;

        // Get info about this frame.
        unw_proc_info_t frame;
        if (unw_get_proc_info(cursor, &frame) != UNW_ESUCCESS)
            return _URC_FATAL_PHASE2_ERROR;

        // If there is a personality routine, tell it we are unwinding.
        if (frame.handler != 0) {
            _Unwind_Personality_Fn personality = (_Unwind_Personality_Fn)frame.handler;
            _Unwind_Action action = _UA_CLEANUP_PHASE;
            unw_word_t sp;
            unw_get_reg(cursor, UNW_REG_SP, &sp);
            if (sp == exception_object->private_2)
                // Tell personality this was the frame it marked in phase 1.
                action = (_Unwind_Action)(_UA_CLEANUP_PHASE | _UA_HANDLER_FRAME);

            _Unwind_Reason_Code reason = (*personality)(1,
                                                        action,
                                                        exception_object->exception_class,
                                                        exception_object,
                                                        (struct _Unwind_Context *)(cursor));
            switch (reason) {
                case _URC_CONTINUE_UNWIND:
                    // Continue unwinding
                    if (sp == exception_object->private_2) {
                        // Phase 1 said we would stop at this frame, but we did not...
                    }
                    break;
                case _URC_INSTALL_CONTEXT:
                    // Personality routine says to transfer control to landing pad.
                    // We may get control back if landing pad calls _Unwind_Resume().
                    unw_resume(cursor);

                    // __unw_phase2_resume() only returns if there was an error.
                    return _URC_FATAL_PHASE2_ERROR;
                default:
                    // Personality routine returned an unknown result code.
                    return _URC_FATAL_PHASE2_ERROR;
            }
        }
    }

    // Clean up phase did not resume at the frame that the search phase
    // said it would...
    return _URC_FATAL_PHASE2_ERROR;
}

static _Unwind_Reason_Code
unwind_phase2_forced(unw_context_t *uc, unw_cursor_t *cursor,
                     _Unwind_Exception *exception_object,
                     _Unwind_Stop_Fn stop, void *stop_parameter)
{
    unw_init_local(cursor, uc);

    // uc is initialized by __unw_getcontext in the parent frame. The first stack
    // frame walked is unwind_phase2_forced.

    // Walk each frame until we reach where search phase said to stop
    while (unw_step(cursor) > 0) {

        // Update info about this frame.
        unw_proc_info_t frame;
        if (unw_get_proc_info(cursor, &frame) != UNW_ESUCCESS)
            return _URC_FATAL_PHASE2_ERROR;

        // Call stop function at each frame.
        _Unwind_Action action = (_Unwind_Action)(_UA_FORCE_UNWIND | _UA_CLEANUP_PHASE);
        _Unwind_Reason_Code reason = (*stop)(1,
                                             action,
                                             exception_object->exception_class,
                                             exception_object,
                                             (struct _Unwind_Context *)(cursor),
                                             stop_parameter);
        if (reason != _URC_NO_REASON)
            return _URC_FATAL_PHASE2_ERROR;

        // If there is a personality routine, tell it we are unwinding.
        if (frame.handler != 0) {
            _Unwind_Personality_Fn personality = (_Unwind_Personality_Fn)frame.handler;
            _Unwind_Reason_Code reason = (*personality)(1,
                                                        action,
                                                        exception_object->exception_class,
                                                        exception_object,
                                                        (struct _Unwind_Context *)(cursor));
            switch (reason) {
                case _URC_CONTINUE_UNWIND:
                    // Destructors called, continue unwinding
                    break;
                case _URC_INSTALL_CONTEXT:
                    // We may get control back if landing pad calls _Unwind_Resume().
                    unw_resume(cursor);
                    break;
                default:
                    // Personality routine returned an unknown result code.
                    return _URC_FATAL_PHASE2_ERROR;
            }
        }
    }

    // Call stop function one last time and tell it we've reached the end
    // of the stack.
    (*stop)(1,
            (_Unwind_Action)(_UA_FORCE_UNWIND | _UA_CLEANUP_PHASE | _UA_END_OF_STACK),
            exception_object->exception_class,
            exception_object,
            (struct _Unwind_Context *)(cursor),
            stop_parameter);

    // Clean up phase did not resume at the frame that the search phase said it
    // would.
    return _URC_FATAL_PHASE2_ERROR;
}

/// Called by __cxa_throw.  Only returns if there is a fatal error.
_Unwind_Reason_Code
_Unwind_RaiseException(_Unwind_Exception *exception_object)
{
    unw_context_t uc;
    unw_cursor_t cursor;
    unw_getcontext(&uc);

    // Mark that this is a non-forced unwind, so _Unwind_Resume()
    // can do the right thing.
    exception_object->private_1 = 0;
    exception_object->private_2 = 0;

    // phase 1: the search phase
    _Unwind_Reason_Code phase1 = unwind_phase1(&uc, &cursor, exception_object);
    if (phase1 != _URC_NO_REASON)
        return phase1;

    // phase 2: the clean up phase
    return unwind_phase2(&uc, &cursor, exception_object);
}

/// When _Unwind_RaiseException() is in phase2, it hands control
/// to the personality function at each frame.  The personality
/// may force a jump to a landing pad in that function, the landing
/// pad code may then call _Unwind_Resume() to continue with the
/// unwinding.  Note: the call to _Unwind_Resume() is from compiler
/// geneated user code.  All other _Unwind_* routines are called
/// by the C++ runtime __cxa_* routines.
///
/// Note: re-throwing an exception (as opposed to continuing the unwind)
/// is implemented by having the code call __cxa_rethrow() which
/// in turn calls _Unwind_Resume_or_Rethrow().
void
_Unwind_Resume(_Unwind_Exception *exception_object)
{
    unw_context_t uc;
    unw_cursor_t cursor;
    unw_getcontext(&uc);

    if (exception_object->private_1 != 0)
        unwind_phase2_forced(&uc,
                             &cursor,
                             exception_object,
                             (_Unwind_Stop_Fn) exception_object->private_1,
                             (void *)exception_object->private_2);
    else
        unwind_phase2(&uc, &cursor, exception_object);

    // Clients assume _Unwind_Resume() does not return, so all we can do is abort.
}

/// Not used by C++.
/// Unwinds stack, calling "stop" function at each frame.
/// Could be used to implement longjmp().
_Unwind_Reason_Code
_Unwind_ForcedUnwind(_Unwind_Exception *exception_object,
                     _Unwind_Stop_Fn stop, void *stop_parameter)
{
    unw_context_t uc;
    unw_cursor_t cursor;
    unw_getcontext(&uc);

    // Mark that this is a forced unwind, so _Unwind_Resume() can do
    // the right thing.
    exception_object->private_1 = (uintptr_t) stop;
    exception_object->private_2 = (uintptr_t) stop_parameter;

    // do it
    return unwind_phase2_forced(&uc, &cursor, exception_object, stop, stop_parameter);
}


/// Called by personality handler during phase 2 to get LSDA for current frame.
uintptr_t
_Unwind_GetLanguageSpecificData(struct _Unwind_Context *context)
{
    unw_cursor_t *cursor = (unw_cursor_t *)context;
    unw_proc_info_t frame;
    uintptr_t result = 0;
    if (unw_get_proc_info(cursor, &frame) == UNW_ESUCCESS)
        result = (uintptr_t)frame.lsda;
    return result;
}


/// Called by personality handler during phase 2 to find the start of the
/// function.
uintptr_t
_Unwind_GetRegionStart(struct _Unwind_Context *context)
{
    unw_cursor_t *cursor = (unw_cursor_t *)context;
    unw_proc_info_t frame;
    uintptr_t result = 0;
    if (unw_get_proc_info(cursor, &frame) == UNW_ESUCCESS)
        result = (uintptr_t)frame.start_ip;
    return result;
}

/// Called by personality handler during phase 2 if a foreign exception
// is caught.
void
_Unwind_DeleteException(_Unwind_Exception *exception_object)
{
    if (exception_object->exception_cleanup != NULL)
        (*exception_object->exception_cleanup)(_URC_FOREIGN_EXCEPTION_CAUGHT,
                                               exception_object);
}

/// Called by personality handler during phase 2 to get register values.
uintptr_t
_Unwind_GetGR(struct _Unwind_Context *context, int index)
{
    unw_cursor_t *cursor = (unw_cursor_t *)context;
    unw_word_t result;
    unw_get_reg(cursor, index, &result);
    return (uintptr_t)result;
}

/// Called by personality handler during phase 2 to alter register values.
void _Unwind_SetGR(struct _Unwind_Context *context, int index, uintptr_t value)
{
    unw_cursor_t *cursor = (unw_cursor_t *)context;
    unw_set_reg(cursor, index, value);
}

/// Called by personality handler during phase 2 to get instruction pointer.
uintptr_t _Unwind_GetIP(struct _Unwind_Context *context)
{
    unw_cursor_t *cursor = (unw_cursor_t *)context;
    unw_word_t result;
    unw_get_reg(cursor, UNW_REG_IP, &result);
    return (uintptr_t)result;
}

/// Called by personality handler during phase 2 to alter instruction pointer,
/// such as setting where the landing pad is, so _Unwind_Resume() will
/// start executing in the landing pad.
void _Unwind_SetIP(struct _Unwind_Context *context, uintptr_t value)
{
    unw_cursor_t *cursor = (unw_cursor_t *)context;
    unw_set_reg(cursor, UNW_REG_IP, value);
}

