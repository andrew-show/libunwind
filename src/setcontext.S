#if defined(__i386__)

    .global unw_setcontext
unw_setcontext:
    movl  4(%esp), %eax  // set up eax and ret on new stack location
    movl  28(%eax), %edx  // edx holds new stack pointer
    subl  $8,%edx
    movl  %edx, 28(%eax) // save new stack pointer to Registers.__registers.esp
    movl  0(%eax), %ebx
    movl  %ebx, 0(%edx) // save Registers.__registers.eax to new stack
    movl  40(%eax), %ebx
    movl  %ebx, 4(%edx) // save Registers.__registers.eip to new stack
    // we now have ret and eax pushed onto where new stack will be
    // restore all registers
    movl  4(%eax), %ebx
    movl   8(%eax), %ecx
    movl  12(%eax), %edx
    movl  16(%eax), %edi
    movl  20(%eax), %esi
    movl  24(%eax), %ebp
    movl  28(%eax), %esp
    // skip ss
    // skip eflags
    popl  %eax  // eax was already pushed on new stack
    ret       // eip was already pushed on new stack

# elif defined(__x86_64__)

    .global unw_setcontext
unw_setcontext: 
    movq  56(%rdi), %rax // rax holds new stack pointer
    subq  $16, %rax
    movq  %rax, 56(%rdi)
    movq  32(%rdi), %rbx  // store new rdi on new stack
    movq  %rbx, 0(%rax)
    movq  128(%rdi), %rbx // store new rip on new stack
    movq  %rbx, 8(%rax)
    // restore all registers
    movq    0(%rdi), %rax
    movq    8(%rdi), %rbx
    movq   16(%rdi), %rcx
    movq   24(%rdi), %rdx
    // restore rdi later
    movq   40(%rdi), %rsi
    movq   48(%rdi), %rbp
    // restore rsp later
    movq   64(%rdi), %r8
    movq   72(%rdi), %r9
    movq   80(%rdi), %r10
    movq   88(%rdi), %r11
    movq   96(%rdi), %r12
    movq  104(%rdi), %r13
    movq  112(%rdi), %r14
    movq  120(%rdi), %r15
    // skip rflags
    // skip cs
    // skip fs
    // skip gs
    movq  56(%rdi), %rsp  // cut back rsp to new location
    pop    %rdi           // rdi was saved here earlier
    ret                  // rip was saved here

#elif defined(__aarch64__)

    .global unw_setcontext
unw_setcontext:
    ldp    x2, x3,  [x0, #0x010]
    ldp    x4, x5,  [x0, #0x020]
    ldp    x6, x7,  [x0, #0x030]
    ldp    x8, x9,  [x0, #0x040]
    ldp    x10,x11, [x0, #0x050]
    ldp    x12,x13, [x0, #0x060]
    ldp    x14,x15, [x0, #0x070]
    // x16 and x17 were clobbered by the call into the unwinder, so no point in
    // restoring them.
    ldp    x18,x19, [x0, #0x090]
    ldp    x20,x21, [x0, #0x0A0]
    ldp    x22,x23, [x0, #0x0B0]
    ldp    x24,x25, [x0, #0x0C0]
    ldp    x26,x27, [x0, #0x0D0]
    ldp    x28,x29, [x0, #0x0E0]
    ldr    x30,     [x0, #0x100]  // restore pc into lr
    
    ldp    d0, d1,  [x0, #0x110]
    ldp    d2, d3,  [x0, #0x120]
    ldp    d4, d5,  [x0, #0x130]
    ldp    d6, d7,  [x0, #0x140]
    ldp    d8, d9,  [x0, #0x150]
    ldp    d10,d11, [x0, #0x160]
    ldp    d12,d13, [x0, #0x170]
    ldp    d14,d15, [x0, #0x180]
    ldp    d16,d17, [x0, #0x190]
    ldp    d18,d19, [x0, #0x1A0]
    ldp    d20,d21, [x0, #0x1B0]
    ldp    d22,d23, [x0, #0x1C0]
    ldp    d24,d25, [x0, #0x1D0]
    ldp    d26,d27, [x0, #0x1E0]
    ldp    d28,d29, [x0, #0x1F0]
    ldr    d30,     [x0, #0x200]
    ldr    d31,     [x0, #0x208]

    // Finally, restore sp. This must be done after the the last read from the
    // context struct, because it is allocated on the stack, and an exception
    // could clobber the de-allocated portion of the stack after sp has been
    // restored.
    ldr    x16,     [x0, #0x0F8]
    ldp    x0, x1,  [x0, #0x000]  // restore x0,x1
    mov    sp,x16                 // restore sp
    ret    x30                  // jump to pc

#elif defined(__powerpc64__)

    .global unw_setcontext
unw_setcontext:
    blr

# else
#  error "Unsupported architecture."
# endif
