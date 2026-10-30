### Driver
At some point in the future, once getting into more “Advanced" stuff this will not be maintained... </br>
For MSVC implementation, you can checkout this [branch](https://github.com/LongpanZhou/KernelDriver/tree/MSVC). </br>

### User
This is the usermode application in ring3, which handles communication and lazy imports... </br>
This will not be updated once getting into "Advanced" stuff </br>

### Command channel
The default build uses the named-section channel in `Driver/Channel.cpp`. The opt-in
`POSTBOX_CHANNEL` build replaces it with the timer/work-item mailbox described in
`docs/CHANNEL.md`; the client-only deployment binary is `User/build/PostboxClient.exe`, while
`User.exe` is the dual-client lab harness. The detection analysis behind the choice is in
`../out/research/AC-25_channel.md`, the detector survey for the implemented channel is in
`../out/research/AC-26_detection_vectors.md`, and the pre-AC/manual-map analysis is in
`../out/research/AC-27_preac_mapping.md`. The default build is not rebuilt with
`POSTBOX_CHANNEL` (its CMake cache reports `POSTBOX_CHANNEL:OFF`), which is a flag check, not a
bit-for-bit baseline claim.