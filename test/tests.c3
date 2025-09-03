module winternitz_tests;

import winternitz;
import std;

Lcg64Random prng;

fn void setup() @init
{
    prng.set_seed(random::entropy()[..]);
}


// module winternitz_tests @test;

// import winternitz;
// import std;

// fn void gen_privkey()
fn void main()
{
    // char[] pkey = x"112233445566778899001020304050607080";
    // winternitz::sign(x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"[..], $power: 32);
    // winternitz::sign(x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"[..], $power: 16);
    WinternitzResult_p16_n32 res = winternitz::sign_sha256("Happy feet!", $power: 16);
    // winternitz::sign(x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"[..], $power: 4);
    // winternitz::sign(x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"[..], $power: 2);

    io::eprintfn("%s", res);
    bool b = winternitz::verify_sha256("Happy feet!", res, $power: 16);
    io::stderr().flush()!!;
}
