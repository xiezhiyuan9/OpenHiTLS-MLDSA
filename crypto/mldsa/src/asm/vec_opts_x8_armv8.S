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

.macro load_data
    ldr q_arr_a1, [arr_a, #1*16]
    ldr q_arr_a2, [arr_a, #2*16]
    ldr q_arr_a3, [arr_a, #3*16]
    ldr q_arr_a0, [arr_a], #4*16

    ldr q_arr_a4, [arr_a, #1*16]
    ldr q_arr_a5, [arr_a, #2*16]
    ldr q_arr_a6, [arr_a, #3*16]
    ldr q_arr_a7, [arr_a], #4*16

    ldr q_arr_b1, [arr_b, #1*16]
    ldr q_arr_b2, [arr_b, #2*16]
    ldr q_arr_b3, [arr_b, #3*16]
    ldr q_arr_b0, [arr_b], #4*16

    ldr q_arr_b4, [arr_b, #1*16]
    ldr q_arr_b5, [arr_b, #2*16]
    ldr q_arr_b6, [arr_b, #3*16]
    ldr q_arr_b7, [arr_b], #4*16
.endm

.macro save_data
    str q_arr_a1, [arr_out, #1*16]
    str q_arr_a2, [arr_out, #2*16]
    str q_arr_a3, [arr_out, #3*16]
    str q_arr_a0, [arr_out], #4*16

    str q_arr_a4, [arr_out, #1*16]
    str q_arr_a5, [arr_out, #2*16]
    str q_arr_a6, [arr_out, #3*16]
    str q_arr_a7, [arr_out], #4*16
.endm

.macro vec_add_mod out, a, b
    // t[i] = a[i] + b[i];
    ADD \out\().4s, \a\().4s, \b\().4s
    // int32_t m = (t[i] + (1 << 22u)) >> 23u;
    // t[i] -= m * MLDSA_Q;
    srshr tmp.4s, \out\().4s, #23
    mls \out\().4s, tmp.4s, const_q.4s
.endm

.macro vec_add_q out, a, b
    // t[i] = a[i] + b[i];
    // t[i] = t[i] + (MLDSA_Q & (t[i] >> 31));
    ADD \out\().4s, \a\().4s, \b\().4s
    ushr tmp.4s, \out\().4s, #31
    mla \out\().4s, tmp.4s, const_q.4s
.endm

.macro vec_sub_mod out, a, b
    // t[i] = a[i] - b[i];
    SUB \out\().4s, \a\().4s, \b\().4s
    // int32_t m = (t[i] + (1 << 22u)) >> 23u;
    // t[i] -= m * MLDSA_Q;
    srshr tmp.4s, \out\().4s, #23
    mls \out\().4s, tmp.4s, const_q.4s
.endm

    arr_out      .req x0
    arr_a      .req x1
    arr_b      .req x2
    count   .req x4
    wtmp    .req w5

    arr_a0     .req v0
    arr_a1     .req v1
    arr_a2     .req v2
    arr_a3     .req v3
    arr_b0     .req v4
    arr_b1     .req v5
    arr_b2     .req v6
    arr_b3     .req v7
    q_arr_a0     .req q0
    q_arr_a1     .req q1
    q_arr_a2     .req q2
    q_arr_a3     .req q3
    q_arr_b0     .req q4
    q_arr_b1     .req q5
    q_arr_b2     .req q6
    q_arr_b3     .req q7

    const_q     .req v31
    tmp         .req v30

    arr_a4      .req v16
    arr_a5      .req v17
    arr_a6      .req v18
    arr_a7      .req v19
    arr_b4      .req v20
    arr_b5      .req v21
    arr_b6      .req v22
    arr_b7      .req v23
    q_arr_a4      .req q16
    q_arr_a5      .req q17
    q_arr_a6      .req q18
    q_arr_a7      .req q19
    q_arr_b4      .req q20
    q_arr_b5      .req q21
    q_arr_b6      .req q22
    q_arr_b7      .req q23

CRYPT_AARCH64_FUNC_START(VecAdd)
VecAdd:
    AARCH64_PACIASP

    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    MOV count, #(256 / 8 / 4)

.loop_add:
    load_data

    vec_add_mod arr_a0, arr_a0, arr_b0
    vec_add_mod arr_a1, arr_a1, arr_b1
    vec_add_mod arr_a2, arr_a2, arr_b2
    vec_add_mod arr_a3, arr_a3, arr_b3
    vec_add_mod arr_a4, arr_a4, arr_b4
    vec_add_mod arr_a5, arr_a5, arr_b5
    vec_add_mod arr_a6, arr_a6, arr_b6
    vec_add_mod arr_a7, arr_a7, arr_b7

    save_data

    subs count, count, #1
    cbnz count, .loop_add

    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(VecAdd)

CRYPT_AARCH64_FUNC_START(VecSub)
VecSub:
    AARCH64_PACIASP
    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    MOV count, #(256 / 8 / 4)

.loop_sub:
    load_data

    vec_sub_mod arr_a0, arr_a0, arr_b0
    vec_sub_mod arr_a1, arr_a1, arr_b1
    vec_sub_mod arr_a2, arr_a2, arr_b2
    vec_sub_mod arr_a3, arr_a3, arr_b3
    vec_sub_mod arr_a4, arr_a4, arr_b4
    vec_sub_mod arr_a5, arr_a5, arr_b5
    vec_sub_mod arr_a6, arr_a6, arr_b6
    vec_sub_mod arr_a7, arr_a7, arr_b7

    save_data

    subs count, count, #1
    cbnz count, .loop_sub

    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(VecSub)

CRYPT_AARCH64_FUNC_START(VecAddq)
VecAddq:
    AARCH64_PACIASP

    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    MOV count, #(256 / 8 / 4)

.loop_addq:
    load_data

    vec_add_q arr_a0, arr_a0, arr_b0
    vec_add_q arr_a1, arr_a1, arr_b1
    vec_add_q arr_a2, arr_a2, arr_b2
    vec_add_q arr_a3, arr_a3, arr_b3
    vec_add_q arr_a4, arr_a4, arr_b4
    vec_add_q arr_a5, arr_a5, arr_b5
    vec_add_q arr_a6, arr_a6, arr_b6
    vec_add_q arr_a7, arr_a7, arr_b7

    save_data

    subs count, count, #1
    cbnz count, .loop_addq

    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(VecAddq)

    .unreq arr_out
    .unreq arr_a
    .unreq arr_b
    .unreq count
    .unreq wtmp

    .unreq arr_a1
    .unreq arr_a2
    .unreq arr_a3
    .unreq arr_a0
    .unreq arr_b1
    .unreq arr_b2
    .unreq arr_b3
    .unreq arr_b0
    .unreq q_arr_a1
    .unreq q_arr_a2
    .unreq q_arr_a3
    .unreq q_arr_a0
    .unreq q_arr_b1
    .unreq q_arr_b2
    .unreq q_arr_b3
    .unreq q_arr_b0
    .unreq const_q
    .unreq tmp
    .unreq arr_a4
    .unreq arr_a5
    .unreq arr_a6
    .unreq arr_a7
    .unreq arr_b4
    .unreq arr_b5
    .unreq arr_b6
    .unreq arr_b7
    .unreq q_arr_a4
    .unreq q_arr_a5
    .unreq q_arr_a6
    .unreq q_arr_a7
    .unreq q_arr_b4
    .unreq q_arr_b5
    .unreq q_arr_b6
    .unreq q_arr_b7
#endif // HITLS_CRYPTO_MLDSA
