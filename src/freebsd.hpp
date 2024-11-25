#include <unistd.h>
#include <stddef.h>
#include <signal.h>
#include <machine/sigframe.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#define PSEUDO_SIGNAL_FRAME 1

#if defined(__x86_64__)

// AMD64 signal frame, struct sigframe
// sys/x86/include/sigframe.h

#define SIGCONTEXT_REG_RDI offsetof(struct sigframe, sf_uc.uc_mcontext.mc_rdi)
#define SIGCONTEXT_REG_RSI offsetof(struct sigframe, sf_uc.uc_mcontext.mc_rsi)
#define SIGCONTEXT_REG_RDX offsetof(struct sigframe, sf_uc.uc_mcontext.mc_rdx)
#define SIGCONTEXT_REG_RCX offsetof(struct sigframe, sf_uc.uc_mcontext.mc_rcx)
#define SIGCONTEXT_REG_R8  offsetof(struct sigframe, sf_uc.uc_mcontext.mc_r8)
#define SIGCONTEXT_REG_R9  offsetof(struct sigframe, sf_uc.uc_mcontext.mc_r9)
#define SIGCONTEXT_REG_RAX offsetof(struct sigframe, sf_uc.uc_mcontext.mc_rax)
#define SIGCONTEXT_REG_RBX offsetof(struct sigframe, sf_uc.uc_mcontext.mc_rbx)
#define SIGCONTEXT_REG_RBP offsetof(struct sigframe, sf_uc.uc_mcontext.mc_rbp)
#define SIGCONTEXT_REG_R10 offsetof(struct sigframe, sf_uc.uc_mcontext.mc_r10)
#define SIGCONTEXT_REG_R11 offsetof(struct sigframe, sf_uc.uc_mcontext.mc_r11)
#define SIGCONTEXT_REG_R12 offsetof(struct sigframe, sf_uc.uc_mcontext.mc_r12)
#define SIGCONTEXT_REG_R13 offsetof(struct sigframe, sf_uc.uc_mcontext.mc_r13)
#define SIGCONTEXT_REG_R14 offsetof(struct sigframe, sf_uc.uc_mcontext.mc_r14)
#define SIGCONTEXT_REG_R15 offsetof(struct sigframe, sf_uc.uc_mcontext.mc_r15)
#define SIGCONTEXT_REG_RIP offsetof(struct sigframe, sf_uc.uc_mcontext.mc_rip)
#define SIGCONTEXT_REG_RSP offsetof(struct sigframe, sf_uc.uc_mcontext.mc_rsp)

#define SIGCONTEXT_REG(reg) SIGCONTEXT_REG_##reg
#define CFA_SAVE DW_CFA_def_cfa_expression, 4, DW_OP_breg7, SLEB128_2(SIGCONTEXT_REG(RSP)), DW_OP_deref
#define REG_SAVE(reg) DW_CFA_expression, UNW_X86_64_##reg, 3, DW_OP_breg7, SLEB128_2(SIGCONTEXT_REG(reg))

SIGNAL_EH_FRAME_DECLARE(signal_eh_frame, UNW_X86_64_RIP, {
    CFA_SAVE,
    REG_SAVE(RDI),
    REG_SAVE(RSI),
    REG_SAVE(RDX),
    REG_SAVE(RCX),
    REG_SAVE(R8),
    REG_SAVE(R9),
    REG_SAVE(RAX),
    REG_SAVE(RBX),
    REG_SAVE(RBP),
    REG_SAVE(R10),
    REG_SAVE(R11),
    REG_SAVE(R12),
    REG_SAVE(R13),
    REG_SAVE(R14),
    REG_SAVE(R15),
    REG_SAVE(RIP),
    DW_CFA_nop,
});

// FreeBSD have call frame in sigtram code in x86-64 system.
#define SIGTRAMP_OFFSET 0

#elif defined(__aarch64__)

#define SIGCONTEXT_REG(reg) offsetof(struct sigframe, sf_uc.uc_mcontext.mc_gpregs.gp_x[UNW_ARM64_##reg])
#define CFA_SAVE DW_CFA_def_cfa_expression, 4, DW_OP_breg31, SLEB128_2(SIGCONTEXT_REG(SP)), DW_OP_deref
#define REG_SAVE(reg) DW_CFA_expression, UNW_ARM64_##reg, 3, DW_OP_breg31, SLEB128_2(SIGCONTEXT_REG(reg))

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
    REG_SAVE(LR),
    REG_SAVE(SP),
    REG_SAVE(PC),
    DW_CFA_nop,
});

// memory before sigcode is reserved as init stack, it's safe to move
// one byte before sigcode
#define SIGTRAMP_OFFSET 1

#else

#undef PSEUDO_SIGNAL_FRAME

#endif

#if defined(PSEUDO_SIGNAL_FRAME)

    static void __attribute__((constructor)) init()
    {
        int name[]= { CTL_KERN, KERN_PROC, KERN_PROC_SIGTRAMP, getpid() };
        static kinfo_sigtramp ksi;
        size_t size = sizeof(ksi);
        if (sysctl(name, 4, &ksi, &size, nullptr, 0) != -1) {
            SIGNAL_EH_FRAME_SET_LOCATION(signal_eh_frame,
                                         (uintptr_t)ksi.ksigtramp_start - SIGTRAMP_OFFSET,
                                         (uintptr_t)ksi.ksigtramp_end - (uintptr_t)ksi.ksigtramp_start) + SIGTRAMP_OFFSET;
        }
    }
#endif // defined(PSEUDO_SIGNAL_FRAME)
