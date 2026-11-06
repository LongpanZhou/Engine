// Locate-by-signature helpers shared by the memory extractors and the trace
// cleaners: the .text-then-.PAGE image scan and the rip-relative displacement
// resolve. This file follows Strings.h in the unity order.

// rip-relative reference -> absolute address: disp32 sits at OffsetOffset, the
// instruction ends after InstructionSize bytes.
address ResolveRipRelative(const void *Instruction, uint32_t OffsetOffset, uint32_t InstructionSize)
{
    auto Instr = (size_t) Instruction;
    int32_t Offset = *(int32_t *) (Instr + OffsetOffset);
    return (address) (Instr + InstructionSize + Offset);
}

// Pattern scan over one module image: .text first, then .PAGE. The section
// scans are quiet; exactly one result is reported after all attempts finish.
static address ScanModuleImageSections(address Base, const char *Sig, size_t Size)
{
    if (!Base)
    {
        print(ERROR("ScanModuleImage: no base address"));
        return nullptr;
    }

    // scan the normal code section first. .PAGE is the paged/rare
    // fallback; putting it first can match a stale paged copy before .text.
    address Match = SectionScan(Base, Decode(TextSectionName).data(), Sig, Size);
    if (!Match)
        Match = SectionScan(Base, Decode(PageSectionName).data(), Sig, Size);

    if (Match)
        print(INFO("Signature: %p"), Match);
    else
        print(ERROR("SIGNATURE NOT FOUND!"));

    return Match;
}

address ScanModuleImage(address Base, const char *Sig, size_t Size)
{
    return ScanModuleImageSections(Base, Sig, Size);
}

// Overload for the length-carrying signatures built by PatternToBytes. Embedded NUL bytes in the
// pattern are part of the pattern, not a terminator.
template<size_t N>
address ScanModuleImage(address Base, const Pattern<N> &Sig)
{
    // A malformed signature must never scan as a real byte pattern. The
    // constexpr check in Strings.h catches it at build time; this is the
    // runtime guard for a pattern built from non-constant input.
    if (!Sig.Valid)
    {
        print(ERROR("ScanModuleImage: invalid signature"));
        return nullptr;
    }
    return ScanModuleImageSections(Base, Sig.data(), Sig.Length);
}
