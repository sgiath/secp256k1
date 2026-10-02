# `c_src/random.h` Windows size check runs after the call

`fill_random` on `_WIN32` passes `size_t size` to `BCryptGenRandom` (which takes a `ULONG`) and only checks `size > ULONG_MAX` after the call, so an oversized request would be silently truncated before the check rejects it. All current callers pass 32 bytes, so this is latent. Fix by checking the size before calling `BCryptGenRandom`.
