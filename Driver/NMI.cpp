// NMI Handler
void NMIInterruptHandler()
{

}

// Page Fault Handler
void PageFaultInterruptHandler()
{

}

// IDT
void IDTHandle()
{


}

void IDTHook()
{
    // IDT
    interrupt_descriptor_table idt = sidt();
    address base = idt.base;
}