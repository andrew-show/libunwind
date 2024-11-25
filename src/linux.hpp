
#define PSEUDO_SIGNAL_FRAME 1

#if defined(__aarch64__)
// ARM64 signal frame: struct rt_sigframe
// After user space signal handler is returned to __kernel_rt_sigreturn
// function, the SP register is pointed to the struct rt_sigframe.
// the registers for stack unwind is saved in sigcontext struct.
//====================================================================================
// Field                    Type        Size        Description
// .info                    siginfo     128
// .sig                     sigframe
//   .uc                    ucontext
//     .uc_flags            __u64       8
//     .uc_link             ucontext *  8
//     .uc_stack            stack_t     24
//     .uc_sigmask          sigset_t    s1
//     .unused[]            __u8        128 - s1
//                          __u64       8           Padding
//     .uc_mcontext         sigcontext              Align to 16 bytes boundary
//       .fault_address     __u64       8
//       .regs[31]          __u64       8 * 31
//       .sp                __u64       8
//       .pc                __u64       8

// The offset to sigcontext.regs
#define SIGCONTEXT_REG(reg) ((128 + 8 + 8 + 24 + 128 + 8 + 8) + (UNW_ARM64_##reg * 8))

#define CFA_SAVE DW_CFA_def_cfa_expression, 4, DW_OP_breg31, SLEB128_2(SIGCONTEXT_REG(SP)), DW_OP_deref
#define REG_SAVE(reg) DW_CFA_expression, UNW_ARM64_##reg, 3, DW_OP_breg31, SLEB128_2(SIGCONTEXT_REG(reg))

// https://github.com/torvalds/linux/blob/master/arch/arm64/kernel/vdso/sigreturn.S
// ARM64 linux vdso doesn't have .eh_frame_hdr for __kernel_rt_sigreturn, construct
// pseudo .eh_frame and .eh_frame_hdr for stack unwinding.

SIGNAL_EH_FRAME_DECLARE(signal_eh_frame, UNW_ARM64_PC, {
    CFA_SAVE,
    REG_SAVE(X0),
    REG_SAVE(X1),
    REG_SAVE(X2),
    REG_SAVE(X3),
    REG_SAVE(X4),
    REG_SAVE(X5),
    REG_SAVE(X6),
    REG_SAVE(X7),
    REG_SAVE(X8),
    REG_SAVE(X9),
    REG_SAVE(X10),
    REG_SAVE(X11),
    REG_SAVE(X12),
    REG_SAVE(X13),
    REG_SAVE(X14),
    REG_SAVE(X15),
    REG_SAVE(X16),
    REG_SAVE(X17),
    REG_SAVE(X18),
    REG_SAVE(X19),
    REG_SAVE(X20),
    REG_SAVE(X21),
    REG_SAVE(X22),
    REG_SAVE(X23),
    REG_SAVE(X24),
    REG_SAVE(X25),
    REG_SAVE(X26),
    REG_SAVE(X27),
    REG_SAVE(X28),
    REG_SAVE(X29),
    REG_SAVE(X30),
    REG_SAVE(PC),
    DW_CFA_nop,
});

#define SIGTRAMP_SYMBOL "__kernel_rt_sigreturn"
#define SIGTRAMP_OFFSET 1   // a nop instruction before __kernel_rt_sigreturn can avoid potential crash
#define SIGTRAMP_RANGE 8

#else     

#undef PSEUDO_SIGNAL_FRAME

#endif

#if defined(PSEUDO_SIGNAL_FRAME)

static void __attribute__((constructor)) init()
{
    void *lib = dlopen("linux-vdso.so.1", RTLD_LAZY);
    if (lib) {
        const void *sigtramp = dlsym(lib, SIGTRAMP_SYMBOL);
        if (sigtramp) {
            SIGNAL_EH_FRAME_SET_LOCATION(signal_eh_frame,
                                         ((uintptr_t)sigtramp) - SIGTRAMP_OFFSET,
                                         SIGTRAMP_RANGE);
        }

        dlclose(lib);
    }
}

#endif // defined(PSEUDO_SIGNAL_FRAME)

