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

// Pattern scan over one module image: PAGE first, then .text, like the reference cleaner's FindPatternImage.
// The section scans are quiet; exactly one result is reported after all attempts are finished.
// Wildcards is optional: raw string callers keep the legacy '?' convention; Pattern callers pass
// the explicit mask so a literal 0x3F byte is compared normally.
static address ScanModuleImageSections(address Base, const char *Sig, size_t Size,
                                       const uint8_t *Wildcards)
{
    if (!Base)
    {
        print(ERROR("ScanModuleImage: no base address"));
        return nullptr;
    }

    // DV-60: scan the normal code section first. .PAGE is the paged/rare
    // fallback; putting it first can match a stale paged copy before .text.
    address Match = SectionScan(Base, Decode(TextSectionName).data(), Sig, Size, Wildcards);
    if (!Match)
        Match = SectionScan(Base, Decode(PageSectionName).data(), Sig, Size, Wildcards);

    if (Match)
        print(INFO("Signature: %p"), Match);
    else
        print(ERROR("SIGNATURE NOT FOUND!"));

    return Match;
}

address ScanModuleImage(address Base, const char *Sig, size_t Size)
{
    return ScanModuleImageSections(Base, Sig, Size, nullptr);
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
    return ScanModuleImageSections(Base, Sig.data(), Sig.Length, Sig.Wildcards.data());
}
