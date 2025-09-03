# winternitz.c3l - WOTS and WOTS+ C3 Library

An implementation of [Winternitz One-Time Signatures](https://eprint.iacr.org/2017/965.pdf) in C3.

As an added implementation, this library will eventually support WOTS+, used in SLH-DSA, LMS, and other post-quantum cryptography.


### TODO
There are a few things that need to be improved:
- [ ] WOTS+ implementation
- [ ] Remove module generics in basic Winternitz OTS (`$w` and `$n` can be runtime macro parameters instead).
