/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MLDSA

#include "crypt_arm.h"

.macro load_const
    // MLDSA_Q = 8380417
    movz wtmp, #0xe001
    movk wtmp, #0x7f, lsl #16
    dup const_q.4s, wtmp

    // MLDSA_Q^-1 = unsigned_mod(pow(MLDSA_Q, -1, 2**32), 2**32)
    // = 58728449
    movz wtmp, #0x2001
    movk wtmp, #0x380, lsl #16
    dup const_q_twisted.4s, wtmp
.endm

.macro montgomery_reduce_long res, inl, inh
    uzp1   \res\().4s, \inl\().4s, \inh\().4s
    mul    \res\().4s, \res\().4s, const_q_twisted.4s
    smlsl  \inl\().2d, \res\().2s, const_q.2s
    smlsl2 \inh\().2d, \res\().4s, const_q.4s
    uzp2   \res\().4s, \inl\().4s, \inh\().4s
.endm

.macro load_polys p0, p1, p2, p3, ptr, idx
.if \idx == 0
    ldr \p1, [\ptr, #1*16]
    ldr \p2, [\ptr, #2*16]
    ldr \p3, [\ptr, #3*16]
    ldr \p0, [\ptr], #4*16
.else
    ldr \p0, [\ptr, #(1024*\idx-4*16)]
    ldr \p1, [\ptr, #(1024*\idx-3*16)]
    ldr \p2, [\ptr, #(1024*\idx-2*16)]
    ldr \p3, [\ptr, #(1024*\idx-1*16)]
.endif
.endm

.macro pmull dl, dh, a, b
    smull  \dl\().2d, \a\().2s, \b\().2s
    smull2 \dh\().2d, \a\().4s, \b\().4s
.endm

.macro pmlal dl, dh, a, b
    smlal  \dl\().2d, \a\().2s, \b\().2s
    smlal2 \dh\().2d, \a\().4s, \b\().4s
.endm

.macro l0_3
    load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 0
    load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 0

    pmull c_0_lo, c_0_hi, arr_a0, arr_b0
    pmull c_1_lo, c_1_hi, arr_a1, arr_b1
    pmull c_2_lo, c_2_hi, arr_a2, arr_b2
    pmull c_3_lo, c_3_hi, arr_a3, arr_b3

    load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 1
    load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 1

    pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pmlal c_3_lo, c_3_hi, arr_a3, arr_b3

    load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 2
    load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 2

    pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pmlal c_3_lo, c_3_hi, arr_a3, arr_b3

    load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 3
    load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 3

    pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pmlal c_3_lo, c_3_hi, arr_a3, arr_b3
.endm

.macro l4
    load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 4
    load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 4

    pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pmlal c_3_lo, c_3_hi, arr_a3, arr_b3
.endm

.macro l5_6
    load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 5
    load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 5

    pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pmlal c_3_lo, c_3_hi, arr_a3, arr_b3

    load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 6
    load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 6

    pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pmlal c_3_lo, c_3_hi, arr_a3, arr_b3
.endm


.macro reduce 
    montgomery_reduce_long arr_a0, c_0_lo, c_0_hi
    montgomery_reduce_long arr_a1, c_1_lo, c_1_hi
    montgomery_reduce_long arr_a2, c_2_lo, c_2_hi
    montgomery_reduce_long arr_a3, c_3_lo, c_3_hi
    // Bounds: |c_{i}| < q
.endm

    out_ptr .req x0
    a_ptr   .req x1
    b_ptr   .req x2
    count   .req x3
    wtmp    .req w3

    const_q         .req v31
    const_q_twisted .req v30

    arr_a0      .req v0
    arr_a1      .req v1
    arr_a2      .req v2
    arr_a3      .req v3
    arr_b0      .req v4
    arr_b1      .req v5
    arr_b2      .req v6
    arr_b3      .req v7
    q_arr_a0    .req q0
    q_arr_a1    .req q1
    q_arr_a2    .req q2
    q_arr_a3    .req q3
    q_arr_b0    .req q4
    q_arr_b1    .req q5
    q_arr_b2    .req q6
    q_arr_b3    .req q7

    c_0_lo   .req v16
    c_0_hi   .req v17
    c_1_lo   .req v18
    c_1_hi   .req v19
    c_2_lo   .req v20
    c_2_hi   .req v21
    c_3_lo   .req v22
    c_3_hi   .req v23

CRYPT_AARCH64_FUNC_START(PolyveclPointwiseAccMontgomeryL4Asm)
PolyveclPointwiseAccMontgomeryL4Asm:
    AARCH64_PACIASP
    load_const
    mov count, #(256 / 4 / 4)

.polyvecl_pointwise_acc_montgomery_l4_loop_start:
    l0_3
    reduce

    str q_arr_a1, [out_ptr, #1*16]
    str q_arr_a2, [out_ptr, #2*16]
    str q_arr_a3, [out_ptr, #3*16]
    str q_arr_a0, [out_ptr], #4*16

    subs count, count, #1
    cbnz count, .polyvecl_pointwise_acc_montgomery_l4_loop_start

AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(PolyveclPointwiseAccMontgomeryL4Asm)

CRYPT_AARCH64_FUNC_START(PolyveclPointwiseAccMontgomeryL5Asm)
PolyveclPointwiseAccMontgomeryL5Asm:
AARCH64_PACIASP
    load_const
    mov count, #(256 / 4 / 4)

.polyvecl_pointwise_acc_montgomery_l5_loop_start:
    l0_3
    l4
    reduce

    str q_arr_a1, [out_ptr, #1*16]
    str q_arr_a2, [out_ptr, #2*16]
    str q_arr_a3, [out_ptr, #3*16]
    str q_arr_a0, [out_ptr], #4*16

    subs count, count, #1
    cbnz count, .polyvecl_pointwise_acc_montgomery_l5_loop_start

AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(PolyveclPointwiseAccMontgomeryL5Asm)

CRYPT_AARCH64_FUNC_START(PolyveclPointwiseAccMontgomeryL7Asm)
PolyveclPointwiseAccMontgomeryL7Asm:
AARCH64_PACIASP
    load_const
    mov count, #(256 / 4 / 4)

.polyvecl_pointwise_acc_montgomery_l7_loop_start:
    l0_3
    l4
    l5_6
    reduce

    str q_arr_a1, [out_ptr, #1*16]
    str q_arr_a2, [out_ptr, #2*16]
    str q_arr_a3, [out_ptr, #3*16]
    str q_arr_a0, [out_ptr], #4*16

    subs count, count, #1
    cbnz count, .polyvecl_pointwise_acc_montgomery_l7_loop_start

AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(PolyveclPointwiseAccMontgomeryL7Asm)

    .unreq out_ptr
    .unreq a_ptr
    .unreq b_ptr
    .unreq count
    .unreq wtmp

    .unreq const_q
    .unreq const_q_twisted

    .unreq arr_a0
    .unreq arr_a1
    .unreq arr_a2
    .unreq arr_a3
    .unreq arr_b0
    .unreq arr_b1
    .unreq arr_b2
    .unreq arr_b3
    .unreq q_arr_a0
    .unreq q_arr_a1
    .unreq q_arr_a2
    .unreq q_arr_a3
    .unreq q_arr_b0
    .unreq q_arr_b1
    .unreq q_arr_b2
    .unreq q_arr_b3
    .unreq c_0_lo
    .unreq c_0_hi
    .unreq c_1_lo
    .unreq c_1_hi
    .unreq c_2_lo
    .unreq c_2_hi
    .unreq c_3_lo
    .unreq c_3_hi
#endif // HITLS_CRYPTO_MLDSA

