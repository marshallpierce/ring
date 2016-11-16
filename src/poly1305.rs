// Copyright 2015-2016 Brian Smith.
// Portions Copyright (c) 2014, 2015, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// TODO: enforce maximum input length.

use {c, chacha, constant_time, error};
use polyfill::slice::u32_from_le_u8;
use std::mem::align_of;
use std::os::raw::c_void;

impl SigningContext {
    #[inline]
    pub fn from_key(key: Key) -> SigningContext {
        let mut ctx = SigningContext{
            _align: [0; 0],
            opaque: [0; BLOCK_STATE_SIZE],
            nonce: [0; 4],
            func: Funcs {
                blocks_fn: GFp_poly1305_blocks,
                emit_fn: GFp_poly1305_emit
            }
        };
        assert!(align_of::<SigningContext>() % 8 == 0);

        let set_fns = init(&mut ctx.opaque, &key.bytes, &mut ctx.func) == 0;
        /* TODO XXX: It seems at least some implementations |poly1305_init| always
         * return the same value, so this conditional logic isn't always necessary.
         * And, for platforms that have such conditional logic also in the ASM code,
         * it seems it would be better to move the conditional logic out of the asm
         * and into the higher-level code. */
        if !set_fns {
            ctx.func.blocks_fn = GFp_poly1305_blocks;
            ctx.func.emit_fn = GFp_poly1305_emit;
        }

        ctx.nonce = [
            u32_from_le_u8(slice_as_array_ref!(&key.bytes[16..20], 4).unwrap()),
            u32_from_le_u8(slice_as_array_ref!(&key.bytes[20..24], 4).unwrap()),
            u32_from_le_u8(slice_as_array_ref!(&key.bytes[24..28], 4).unwrap()),
            u32_from_le_u8(slice_as_array_ref!(&key.bytes[28..32], 4).unwrap()),
        ];
        ctx
    }

    pub fn update_padded(&mut self, input: &[u8]) {
        self.update_padded_inner(input, 1);
    }

    pub fn update_final(mut self, input: &[u8], tag_out: &mut Tag) {
        self.update_padded_inner(input, 0);
        self.func.emit(&mut self.opaque, tag_out, &self.nonce);
    }

    fn update_padded_inner(&mut self, input: &[u8], pad_bit: u8) {
        let todo = input.len() & !0xf; // TODO: name constant
        let (complete_blocks, remainder) = input.split_at(todo);
        self.func.blocks(&mut self.opaque, complete_blocks, 1);
        if !remainder.is_empty() {
            let mut block = [0u8; 16]; // TODO: name constant
            block[..remainder.len()].copy_from_slice(remainder);
            block[remainder.len()] = (!pad_bit) & 1;
            self.func.blocks(&mut self.opaque, &block, pad_bit.into());
        }
    }
}

pub fn verify(key: Key, msg: &[u8], tag: &Tag)
              -> Result<(), error::Unspecified> {
    let mut calculated_tag = [0u8; TAG_LEN];
    sign(key, msg, &mut calculated_tag);
    constant_time::verify_slices_are_equal(&calculated_tag[..], tag)
}

pub fn sign(key: Key, msg: &[u8], tag: &mut Tag) {
    let ctx = SigningContext::from_key(key);
    ctx.update_final(msg, tag);
}

/// A Poly1305 key.
pub struct Key {
    bytes: KeyBytes,
}

impl Key {
    pub fn derive_using_chacha(chacha20_key: &chacha::Key,
                               counter: &chacha::Counter) -> Key {
        let mut bytes = [0u8; KEY_LEN];
        chacha::chacha20_xor_in_place(chacha20_key, counter, &mut bytes);
        Key { bytes: bytes }
    }

    #[cfg(test)]
    pub fn from_test_vector(bytes: &[u8; KEY_LEN]) -> Key {
        Key { bytes: *bytes }
    }
}

type KeyBytes = [u8; KEY_LEN];

/// The length of a `key`.
pub const KEY_LEN: usize = 32;

/// A Poly1305 tag.
pub type Tag = [u8; TAG_LEN];

/// The length of a `Tag`.
pub const TAG_LEN: usize = 128 / 8;

const BLOCK_STATE_SIZE: usize = 192;

#[repr(C)]
struct Funcs {
    blocks_fn: unsafe extern fn(*mut c_void, *const u8, c::size_t, u32), 
    emit_fn: unsafe extern fn(*mut c_void, *mut u8, *const u32),
}

fn init(state: &mut [u8; BLOCK_STATE_SIZE], key: &[u8; KEY_LEN], func: *mut Funcs) -> i32 {
    unsafe {
        GFp_poly1305_init_asm(
            state.as_mut_ptr() as *mut c_void,
            key.as_ptr(),
            func as *mut c_void
        )
    }
}

impl Funcs {
    fn blocks(&self, state: &mut [u8; BLOCK_STATE_SIZE], data: &[u8], should_pad: u32) {
        unsafe {
            (self.blocks_fn)(
                state.as_mut_ptr() as *mut c_void,
                data.as_ptr(),
                data.len(),
                should_pad
            )
        };
    }

    fn emit(&self, state: &mut [u8; BLOCK_STATE_SIZE], tag: &mut Tag, nonce: &[u32; 4]) {
        unsafe {
             (self.emit_fn)(
                 state.as_mut_ptr() as *mut c_void,
                 tag.as_mut_ptr(),
                 nonce.as_ptr()
             );
        }
    }
}

#[repr(C)]
pub struct SigningContext {
    _align: [u64; 0],
    opaque: [u8; BLOCK_STATE_SIZE],
    nonce: [u32; 4],
    func: Funcs
}

extern {
    fn GFp_poly1305_init_asm(state: *mut c_void, key: *const u8, out_func: *mut c_void) -> c::int;
    fn GFp_poly1305_blocks(ctx: *mut c_void, _in: *const u8, len: c::size_t, padbit: u32);
    fn GFp_poly1305_emit(ctx: *mut c_void, mac: *mut u8, nonce: *const u32);
}

#[cfg(test)]
mod tests {
    use test;
    use super::*;

    // Adapted from BoringSSL's crypto/poly1305/poly1305_test.cc.
    #[test]
    pub fn test_poly1305() {
        test::from_file("src/poly1305_test.txt", |section, test_case| {
            assert_eq!(section, "");
            let key = test_case.consume_bytes("Key");
            let key = slice_as_array_ref!(&key, KEY_LEN).unwrap();
            let input = test_case.consume_bytes("Input");
            let expected_mac = test_case.consume_bytes("MAC");
            let expected_mac =
                slice_as_array_ref!(&expected_mac, TAG_LEN).unwrap();

            // Test single-shot operation.
            {
                let key = Key::from_test_vector(&key);
                let ctx = SigningContext::from_key(key);
                let mut actual_mac = [0; TAG_LEN];
                ctx.update_final(&input, &mut actual_mac);
                assert_eq!(&expected_mac[..], &actual_mac[..]);
            }
            {
                let key = Key::from_test_vector(&key);
                let mut actual_mac = [0; TAG_LEN];
                sign(key, &input, &mut actual_mac);
                assert_eq!(&expected_mac[..], &actual_mac[..]);
            }
            {
                let key = Key::from_test_vector(&key);
                assert_eq!(Ok(()), verify(key, &input, &expected_mac));
            }

            // Test streaming block-by-block.
            {
                let key = Key::from_test_vector(&key);
                let mut ctx = SigningContext::from_key(key);
                // TODO: Name "16"
                let all_but_last_len = if input.len() <= 16 {
                    0
                } else if input.len() % 16 != 0 {
                    input.len() - (input.len() % 16)
                } else {
                    input.len() - 16
                };
                let (all_but_last, remaining) = input.split_at(all_but_last_len);
                for chunk in all_but_last.chunks(16) {
                    ctx.update_padded(chunk);
                }
                let mut actual_mac = [0u8; TAG_LEN];
                ctx.update_final(remaining, &mut actual_mac);
                assert_eq!(&expected_mac[..], &actual_mac[..]);
            }

            // XXX
            //try!(test_poly1305_simd(0, key, &input, expected_mac));
            //try!(test_poly1305_simd(16, key, &input, expected_mac));
            //try!(test_poly1305_simd(32, key, &input, expected_mac));
            //try!(test_poly1305_simd(48, key, &input, expected_mac));

            Ok(())
        })
    }

/* XXX: We need to update this test, but it isn't obvious how to do so yet.
    fn test_poly1305_simd(excess: usize, key: &[u8; KEY_LEN], input: &[u8],
                          expected_mac: &[u8; TAG_LEN])
                          -> Result<(), error::Unspecified> {
        let key = Key::from_test_vector(&key);
        let mut ctx = SigningContext::from_key(key);

        // Some implementations begin in non-SIMD mode and upgrade on demand.
        // Stress the upgrade path.
        let init = core::cmp::min(input.len(), 16);
        ctx.update(&input[..init]);

        let long_chunk_len = 128 + excess;
        for chunk in input[init..].chunks(long_chunk_len + excess) {
            if chunk.len() > long_chunk_len {
                let (long, short) = chunk.split_at(long_chunk_len);

                // Feed 128 + |excess| bytes to test SIMD mode.
                ctx.update(long);

                // Feed |excess| bytes to ensure SIMD mode can handle short
                // inputs.
                ctx.update(short);
            } else {
                // Handle the last chunk.
                ctx.update(chunk);
            }
        }

        let mut actual_mac = [0u8; TAG_LEN];
        ctx.sign(&mut actual_mac);
        assert_eq!(&expected_mac[..], &actual_mac);

        Ok(())
    }
*/
}
