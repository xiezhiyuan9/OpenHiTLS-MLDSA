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
    ldr q_r0_data0, [arr_r0]
    ldr q_r0_data1, [arr_r0, #1*16]
    ldr q_r0_data2, [arr_r0, #2*16]
    ldr q_r0_data3, [arr_r0, #3*16]
.endm

.macro save_data
    str q_r0_data1, [arr_r0, #1*16]
    str q_r0_data2, [arr_r0, #2*16]
    str q_r0_data3, [arr_r0, #3*16]
    str q_r0_data0, [arr_r0], #4*16

    str q_r1_data1, [arr_r1, #1*16]
    str q_r1_data2, [arr_r1, #2*16]
    str q_r1_data3, [arr_r1, #3*16]
    str q_r1_data0, [arr_r1], #4*16
.endm

.macro finit arr
    // w[i][j] = w[i][j] + (MLDSA_Q & (w[i][j] >> 31))
    EOR tmp1.16b, tmp1.16b, tmp1.16b        // tmp1 == 0
    CMLT tmp.4s, \arr\().4s, #0
    BSL tmp.16b, const_q.16b, tmp1.16b
    ADD \arr\().4s, \arr\().4s, tmp.4s
.endm

.macro finit_all
    finit r0_data0
    finit r0_data1
    finit r0_data2
    finit r0_data3
.endm

.macro decompose a1, a, roundbit
    // a1 = round-(a / 2*gamma2)  round(a * barrett / 2^48 or 2^49), 
    // for decompose 33: roundbit = 18, 2*gamma2 = 523776 -> barrett = 1074791425
    // for decompose 88: roundbit = 17, 2*gamma2 = 190464 -> barrett = 1477838209
    sqdmulh \a1\().4s, \a\().4s, const_barrett.4s
    srshr \a1\().4s, \a1\().4s, \roundbit

    // Check for wrap-around
    cmgt tmp.4s, \a\().4s, const_q_bound.4s

    // Compute remainder a0
    mls \a\().4s, \a1\().4s, const_2x_gamma2.4s

    // If wrap-around is required, set a1 = 0 and a0 -= 1
    bic \a1\().16b, \a1\().16b, tmp.16b
    add \a\().4s, \a\().4s, tmp.4s
.endm

    arr_r0      .req x0
    arr_r1      .req x1
    count       .req x4
    wtmp        .req w5

    r0_data0        .req v0
    r0_data1        .req v1
    r0_data2        .req v2
    r0_data3        .req v3
    r1_data0        .req v4
    r1_data1        .req v5
    r1_data2        .req v6
    r1_data3        .req v7
    q_r0_data0      .req q0
    q_r0_data1      .req q1
    q_r0_data2      .req q2
    q_r0_data3      .req q3
    q_r1_data0      .req q4
    q_r1_data1      .req q5
    q_r1_data2      .req q6
    q_r1_data3      .req q7

    const_q             .req v31
    const_2x_gamma2     .req v30
    const_q_bound       .req v29
    const_barrett       .req v28

    tmp             .req v27
    tmp1            .req v26

CRYPT_AARCH64_FUNC_START(BatchDecompose32)
BatchDecompose32:
    AARCH64_PACIASP
    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    // 2*GAMMA2 = 523776
    movz wtmp, #0xfe00
    movk wtmp, #7, lsl #16
    dup const_2x_gamma2.4s, wtmp

    // 31*GAMMA2 = 8118528
    movz wtmp, #0xe100
    movk wtmp, #0x7b, lsl #16
    dup const_q_bound.4s, wtmp

    // Barrett constant = 1074791425
    movz wtmp, #0x0401
    movk wtmp, #0x4010, lsl #16
    dup const_barrett.4s, wtmp

    MOV count, #(256 / 4 / 4)

.loop_32:
    load_data
    finit_all

    decompose r1_data0, r0_data0, #18
    decompose r1_data1, r0_data1, #18
    decompose r1_data2, r0_data2, #18
    decompose r1_data3, r0_data3, #18

    save_data

    subs count, count, #1
    cbnz count, .loop_32
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(BatchDecompose32)

CRYPT_AARCH64_FUNC_START(BatchDecompose88)
BatchDecompose88:
AARCH64_PACIASP
    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    // 2*GAMMA2 = 190464
    movz wtmp, #0xe800
    movk wtmp, #0x2, lsl #16
    dup const_2x_gamma2.4s, wtmp

    // 31*GAMMA2 = 8285184
    movz wtmp, #0x6c00
    movk wtmp, #0x7e, lsl #16
    dup const_q_bound.4s, wtmp

    // Barrett constant = 1477838209
    movz wtmp, #0x0581
    movk wtmp, #0x5816, lsl #16
    dup const_barrett.4s, wtmp

    MOV count, #(256 / 4 / 4)

.loop_88:
    load_data
    finit_all

    decompose r1_data0, r0_data0, #17
    decompose r1_data1, r0_data1, #17
    decompose r1_data2, r0_data2, #17
    decompose r1_data3, r0_data3, #17

    save_data

    subs count, count, #1
    cbnz count, .loop_88
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(BatchDecompose88)

    .unreq arr_r0
    .unreq arr_r1
    .unreq count
    .unreq wtmp

    .unreq r0_data0
    .unreq r0_data1
    .unreq r0_data2
    .unreq r0_data3
    .unreq r1_data0
    .unreq r1_data1
    .unreq r1_data2
    .unreq r1_data3
    .unreq q_r0_data0
    .unreq q_r0_data1
    .unreq q_r0_data2
    .unreq q_r0_data3
    .unreq q_r1_data0
    .unreq q_r1_data1
    .unreq q_r1_data2
    .unreq q_r1_data3
    .unreq const_q
    .unreq const_2x_gamma2
    .unreq const_q_bound
    .unreq const_barrett
    .unreq tmp
    .unreq tmp1

#endif // HITLS_CRYPTO_MLDSA