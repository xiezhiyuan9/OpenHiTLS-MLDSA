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
#define MLDSA_D 13
#define MLDSA_D_SUB_1 12

.macro load_data
    ldr q_arr_b0, [arr_t1]
    ldr q_arr_b1, [arr_t1, #1*16]
    ldr q_arr_b2, [arr_t1, #2*16]
    ldr q_arr_b3, [arr_t1, #3*16]
    ldr q_arr_b4, [arr_t1, #4*16]
    ldr q_arr_b5, [arr_t1, #5*16]
    ldr q_arr_b6, [arr_t1, #6*16]
    ldr q_arr_b7, [arr_t1, #7*16]
.endm

.macro save_data
    str q_arr_a1, [arr_t0, #1*16]
    str q_arr_a2, [arr_t0, #2*16]
    str q_arr_a3, [arr_t0, #3*16]
    str q_arr_a4, [arr_t0, #4*16]
    str q_arr_a5, [arr_t0, #5*16]
    str q_arr_a6, [arr_t0, #6*16]
    str q_arr_a7, [arr_t0, #7*16]
    str q_arr_a0, [arr_t0], #8*16

    str q_arr_b1, [arr_t1, #1*16]
    str q_arr_b2, [arr_t1, #2*16]
    str q_arr_b3, [arr_t1, #3*16]
    str q_arr_b4, [arr_t1, #4*16]
    str q_arr_b5, [arr_t1, #5*16]
    str q_arr_b6, [arr_t1, #6*16]
    str q_arr_b7, [arr_t1, #7*16]
    str q_arr_b0, [arr_t1], #8*16
.endm

.macro power2round t1, t0
    // int32_t tmp = (t1 + (1 << (13 - 1)) - 1) >> 13;
    // t0 = t1 - (tmp << 13);
    // t1 = tmp;
    ADD tmp.4s, \t1\().4s, const_12u_sub_1.4s // t1 + 1 << 12 - 1
    SSHR tmp.4s, tmp.4s, #13 // (t1 + 1 << 12 - 1) >> 13
    SHL \t0\().4s, tmp.4s, #13 // tmp << 13
    SUB \t0\().4s, \t1\().4s, \t0\().4s
    MOV \t1\().16b, tmp.16b
.endm

    arr_t0      .req x0
    arr_t1      .req x1

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

    const_12u_sub_1     .req v31
    tmp         .req v30
    tmp1        .req v29

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
 
CRYPT_AARCH64_FUNC_START(VecPower2round)
VecPower2round:
AARCH64_PACIASP

    # 0x1000 - 1 = #0xFFF 
    mov wtmp, #0x0FFF
    dup const_12u_sub_1.4s, wtmp

    MOV count, #(256 / 8 / 4)

.loop:
    load_data

    power2round arr_b0, arr_a0
    power2round arr_b1, arr_a1
    power2round arr_b2, arr_a2
    power2round arr_b3, arr_a3
    power2round arr_b4, arr_a4
    power2round arr_b5, arr_a5
    power2round arr_b6, arr_a6
    power2round arr_b7, arr_a7

    save_data

    subs count, count, #1
    cbnz count, .loop

AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(VecPower2round)

    .unreq arr_t0
    .unreq arr_t1
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
    .unreq const_12u_sub_1
    .unreq tmp
    .unreq tmp1
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