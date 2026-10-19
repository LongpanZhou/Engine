// Locate-by-signature helpers shared by the memory extractors, the hook and the trace cleaners:
// the PAGE-then-.text image scan and the rip-relative displacement resolve. This file sits right
// after Strings.h in the unity order: it needs the encoded section names, while Scan.cpp (which
// Strings.h depends on for PatternToBytes) must stay above Strings.h and cannot host them

// rip-relative reference -> absolute address: disp32 sits at OffsetOffset, the instruction ends after
// InstructionSize bytes (the reference cleaner's ResolveRelativeAddress, renamed)
address ResolveRipRelative(const void *Instruction, uint32_t OffsetOffset, uint32_t InstructionSize)
{
    auto Instr = (size_t) Instruction;
    int32_t Offset = *(int32_t *) (Instr + OffsetOffset);
    return (address) (Instr + InstructionSize + Offset);
}

// Pattern scan over one module image: PAGE first, then .text, like the reference cleaner's FindPatternImage
address ScanModuleImage(address Base, const char *Pattern)
{
    if (!Base)
    {
        print(ERROR("ScanModuleImage: no base address"));
        return nullptr;
    }

    if (address Match = SectionScan(Base, Decode(PageSectionName).data(), Pattern))
        return Match;

    return SectionScan(Base, Decode(TextSectionName).data(), Pattern);
}
