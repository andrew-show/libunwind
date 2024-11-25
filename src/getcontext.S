
#if defined(__i386__)

    .global unw_getcontext
unw_getcontext: 
    push  %eax
    movl  8(%esp), %eax
    movl  %ebx,  4(%eax)
    movl  %ecx,  8(%eax)
    movl  %edx, 12(%eax)
    movl  %edi, 16(%eax)
    movl  %esi, 20(%eax)
    movl  %ebp, 24(%eax)
    movl  %esp, %edx
    addl  $8, %edx
    movl  %edx, 28(%eax) // store what sp was at call site as esp
    // skip ss
    // skip eflags
    movl  4(%esp), %edx
    movl  %edx, 40(%eax)  // store return address as eip
    // skip cs
    // skip ds
    // skip es
    // skip fs
    // skip gs
    popl  %edx
    movl  %edx, (%eax)  // store original eax
    xorl  %eax, %eax
    ret

# elif defined(__x86_64__)

    .global unw_getcontext
unw_getcontext: 
    movq  %rax,   (%rdi)
    movq  %rbx,  8(%rdi)
    movq  %rcx, 16(%rdi)
    movq  %rdx, 24(%rdi)
    movq  %rdi, 32(%rdi)
    movq  %rsi, 40(%rdi)
    movq  %rbp, 48(%rdi)
    movq  %rsp, 56(%rdi)
    addq  $8,   56(%rdi)
    movq  %r8,  64(%rdi)
    movq  %r9,  72(%rdi)
    movq  %r10, 80(%rdi)
    movq  %r11, 88(%rdi)
    movq  %r12, 96(%rdi)
    movq  %r13,104(%rdi)
    movq  %r14,112(%rdi)
    movq  %r15,120(%rdi)
    movq  (%rsp),%rsi
    movq  %rsi,128(%rdi)  // store return address as rip
    // skip rflags
    // skip cs
    // skip fs
    // skip gs
    xorl  %eax, %eax
    ret

#elif defined(__aarch64__)

    .global unw_getcontext
unw_getcontext: 
    stp    x0, x1,  [x0, #0x000]
    stp    x2, x3,  [x0, #0x010]
    stp    x4, x5,  [x0, #0x020]
    stp    x6, x7,  [x0, #0x030]
    stp    x8, x9,  [x0, #0x040]
    stp    x10,x11, [x0, #0x050]
    stp    x12,x13, [x0, #0x060]
    stp    x14,x15, [x0, #0x070]
    stp    x16,x17, [x0, #0x080]
    stp    x18,x19, [x0, #0x090]
    stp    x20,x21, [x0, #0x0A0]
    stp    x22,x23, [x0, #0x0B0]
    stp    x24,x25, [x0, #0x0C0]
    stp    x26,x27, [x0, #0x0D0]
    stp    x28,x29, [x0, #0x0E0]
    str    x30,     [x0, #0x0F0]
    mov    x1,sp
    str    x1,      [x0, #0x0F8]
    str    x30,     [x0, #0x100]    // store return address as pc
    // skip cpsr
    stp    d0, d1,  [x0, #0x110]
    stp    d2, d3,  [x0, #0x120]
    stp    d4, d5,  [x0, #0x130]
    stp    d6, d7,  [x0, #0x140]
    stp    d8, d9,  [x0, #0x150]
    stp    d10,d11, [x0, #0x160]
    stp    d12,d13, [x0, #0x170]
    stp    d14,d15, [x0, #0x180]
    stp    d16,d17, [x0, #0x190]
    stp    d18,d19, [x0, #0x1A0]
    stp    d20,d21, [x0, #0x1B0]
    stp    d22,d23, [x0, #0x1C0]
    stp    d24,d25, [x0, #0x1D0]
    stp    d26,d27, [x0, #0x1E0]
    stp    d28,d29, [x0, #0x1F0]
    str    d30,     [x0, #0x200]
    str    d31,     [x0, #0x208]
    mov    x0, #0                   // return UNW_ESUCCESS
    ret

#elif defined(__powerpc64__)

    .global unw_getcontext
unw_getcontext: 
    // save GPRs
    stdu    %r0, 0(%r3)
    stdu    %r1, 8(%r3)
    stdu    %r2, 8(%r3)
    stdu    %r3, 8(%r3)
    stdu    %r4, 8(%r3)
    stdu    %r5, 8(%r3)
    stdu    %r6, 8(%r3)
    stdu    %r7, 8(%r3)
    stdu    %r8, 8(%r3)
    stdu    %r9, 8(%r3)
    stdu    %r10, 8(%r3)
    stdu    %r11, 8(%r3)
    stdu    %r12, 8(%r3)
    stdu    %r13, 8(%r3)
    stdu    %r14, 8(%r3)
    stdu    %r15, 8(%r3)
    stdu    %r16, 8(%r3)
    stdu    %r17, 8(%r3)
    stdu    %r18, 8(%r3)
    stdu    %r19, 8(%r3)
    stdu    %r20, 8(%r3)
    stdu    %r21, 8(%r3)
    stdu    %r22, 8(%r3)
    stdu    %r23, 8(%r3)
    stdu    %r24, 8(%r3)
    stdu    %r25, 8(%r3)
    stdu    %r26, 8(%r3)
    stdu    %r27, 8(%r3)
    stdu    %r28, 8(%r3)
    stdu    %r29, 8(%r3)
    stdu    %r30, 8(%r3)
    stdu    %r31, 8(%r3)

    mfcr    %r4
    stdu    %r4, 8(%r3) // store cr
    mfxer   %r5
    stdu    %r5, 8(%r3) // store xer
    mflr    %r6
    stdu    %r6, 8(%r3) // store lr
    mfctr   %r7
    stdu    %r7, 8(%r3) // store ctr
    stdu    %r6, 8(%r3) // store lr as pc
    mfvrsave %r8
    stdu    %r8, 8(%r3) // store vrsave


#if defined(__VSX__)
    // save VS registers
    // (note that this also saves floating point registers and V registers,
    // because part of VS is mapped to these registers)

    addi    %r3, %r3, 8

    stxvd2x %vs0, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs1, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs2, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs3, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs4, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs5, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs6, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs7, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs8, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs9, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs10, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs11, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs12, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs13, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs14, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs15, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs16, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs17, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs18, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs19, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs20, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs21, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs22, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs23, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs24, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs25, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs26, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs27, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs28, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs29, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs30, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs31, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs32, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs33, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs34, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs35, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs36, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs37, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs38, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs39, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs40, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs41, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs42, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs43, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs44, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs45, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs46, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs47, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs48, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs49, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs50, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs51, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs52, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs53, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs54, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs55, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs56, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs57, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs58, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs59, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs60, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs61, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs62, 0, %r3
    addi    %r3, %r3, 16
    stxvd2x %vs63, 0, %r3
    addi    %r3, %r3, 16

#else
    // save float registers

    stfdu   %f0, 8(%r3)
    stfdu   %f1, 16(%r3)
    stfdu   %f2, 16(%r3)
    stfdu   %f3, 16(%r3)
    stfdu   %f4, 16(%r3)
    stfdu   %f5, 16(%r3)
    stfdu   %f6, 16(%r3)
    stfdu   %f7, 16(%r3)
    stfdu   %f8, 16(%r3)
    stfdu   %f9, 16(%r3)
    stfdu   %f10, 16(%r3)
    stfdu   %f11, 16(%r3)
    stfdu   %f12, 16(%r3)
    stfdu   %f13, 16(%r3)
    stfdu   %f14, 16(%r3)
    stfdu   %f15, 16(%r3)
    stfdu   %f16, 16(%r3)
    stfdu   %f17, 16(%r3)
    stfdu   %f18, 16(%r3)
    stfdu   %f19, 16(%r3)
    stfdu   %f20, 16(%r3)
    stfdu   %f21, 16(%r3)
    stfdu   %f22, 16(%r3)
    stfdu   %f23, 16(%r3)
    stfdu   %f24, 16(%r3)
    stfdu   %f25, 16(%r3)
    stfdu   %f26, 16(%r3)
    stfdu   %f27, 16(%r3)
    stfdu   %f28, 16(%r3)
    stfdu   %f29, 16(%r3)
    stfdu   %f30, 16(%r3)
    stfdu   %f31, 16(%r3)

#if defined(__ALTIVEC__)
    // save vector registers

    addi    %r3, %r3, 16
    stvx    %v0, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v1, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v2, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v3, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v4, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v5, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v6, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v7, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v8, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v9, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v10, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v11, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v12, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v13, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v14, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v15, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v16, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v17, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v18, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v19, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v20, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v21, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v22, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v23, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v24, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v25, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v26, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v27, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v28, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v29, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v30, 0, %r3

    addi    %r3, %r3, 16
    stvx    %v31, 0, %r3

#endif
#endif

    li    %r3,  0   // return UNW_ESUCCESS
    blr

# else
#  error "Unsupported architecture."
# endif
