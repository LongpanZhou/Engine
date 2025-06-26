interrupt_descriptor localIDT[256];

extern "C" void asm_nmi_handler();

// NMI Handler
void NMIInterruptHandler()
{
    // Save all registers
    asm volatile (
        "push %%rax;"
        "push %%rbx;"
        "push %%rcx;"
        "push %%rdx;"
        "push %%rsi;"
        "push %%rdi;"
        "push %%rbp;"
        "push %%r8;"
        "push %%r9;"
        "push %%r10;"
        "push %%r11;"
        "push %%r12;"
        "push %%r13;"
        "push %%r14;"
        "push %%r15;"
        "mov %%rsp, %%rcx;"         // Pass parameter
        "sub $0x40, %%rsp;"
        :
        :
        : "memory", "rcx");

    rdmsr(0x81);


    asm volatile (
        "add $0x40, %%rsp;"
        "pop %%rax;"
        "pop %%rbx;"
        "pop %%rcx;"
        "pop %%rdx;"
        "pop %%rsi;"
        "pop %%rdi;"
        "pop %%rbp;"
        "pop %%r8;"
        "pop %%r9;"
        "pop %%r10;"
        "pop %%r11;"
        "pop %%r12;"
        "pop %%r13;"
        "pop %%r14;"
        "pop %%r15;"
        :
        :
        : "memory");
}

// Page Fault Handler
void PageFaultInterruptHandler()
{

}

interrupt_descriptor CreateInterruptHandler(interrupt_descriptor WindowsGate, address Handler)
{
    interrupt_descriptor handler{};
}

// IDT
void IDTHandle()
{

}

bool IDTHook()
{
    // Get windows IDT
    auto windowsIDT = (interrupt_descriptor*)sidt().base;
    if (!windowsIDT) return false;

    // Construct local handler
    memcpy(localIDT, windowsIDT, sizeof(localIDT));

    // NMI
    localIDT[2] = CreateInterruptHandler(windowsIDT[2], &NMIInterruptHandler);

    // PF
    localIDT[14] = CreateInterruptHandler(windowsIDT[14], &PageFaultInterruptHandler);

    // Write G/I DTR
    lidt({.base = &localIDT, .limit = sizeof(localIDT)});

    return true;
}

bool IDTUnHook()
{

}