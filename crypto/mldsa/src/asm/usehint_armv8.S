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
    ldr q_data0, [in]
    ldr q_data1, [in, #1*16]
    ldr q_data2, [in, #2*16]
    ldr q_data3, [in, #3*16]

    ldr q_h_data1, [h_arr, #1*16]
    ldr q_h_data2, [h_arr, #2*16]
    ldr q_h_data3, [h_arr, #3*16]
    ldr q_h_data0, [h_arr], #4*16
.endm

.macro save_data
    str q_out1, [in, #1*16]
    str q_out2, [in, #2*16]
    str q_out3, [in, #3*16]
    str q_out0, [in], #4*16
.endm

.macro finit arr
    // w[i][j] = w[i][j] + (MLDSA_Q & (w[i][j] >> 31))
    EOR tmp1.16b, tmp1.16b, tmp1.16b        // tmp1 == 0
    CMLT tmp.4s, \arr\().4s, #0
    BSL tmp.16b, const_q.16b, tmp1.16b
    ADD \arr\().4s, \arr\().4s, tmp.4s
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

.macro use_hint32 b, a, h
    decompose \b, \a, #18

    // delta = (a0 <= 0) ? -1 : 1
    cmle \a\().4s, \a\().4s, #0
    orr \a\().4s, #1

    // b = (b + delta * h) % 16
    mla \b\().4s, \a\().4s, \h\().4s
    and \b\().16b, \b\().16b, mask_15.16b
.endm

.macro use_hint88 b, a, h
    decompose \b, \a, #17

    // delta = (a0 <= 0) ? -1 : 1
    cmle \a\().4s, \a\().4s, #0
    orr \a\().4s, #1

    // b = (b + delta * h) % 44
    mla \b\().4s, \a\().4s, \h\().4s
    cmgt tmp.4s, \b\().4s, const_43.4s
    bic \b\().16b, \b\().16b, tmp.16b
    umin \b\().4s, \b\().4s, const_43.4s
.endm

.macro push_stack
    sub sp, sp, #(16*4)
    stp  d8,  d9, [sp, #16*0]
    stp d10, d11, [sp, #16*1]
    stp d12, d13, [sp, #16*2]
    stp d14, d15, [sp, #16*3]
.endm

.macro pop_stack
    ldp  d8,  d9, [sp, #16*0]
    ldp d10, d11, [sp, #16*1]
    ldp d12, d13, [sp, #16*2]
    ldp d14, d15, [sp, #16*3]
    add sp, sp, #(16*4)
.endm

    in          .req x0
    h_arr       .req x1
    count       .req x4
    wtmp        .req w5

    data0       .req v0
    data1       .req v1
    data2       .req v2
    data3       .req v3
    q_data0     .req q0
    q_data1     .req q1
    q_data2     .req q2
    q_data3     .req q3

    out0        .req v4
    out1        .req v5
    out2        .req v6
    out3        .req v7
    q_out0      .req q4
    q_out1      .req q5
    q_out2      .req q6
    q_out3      .req q7

    tmp                 .req v8
    tmp1                .req v9

    const_q             .req v10
    const_2x_gamma2     .req v11
    const_q_bound       .req v12
    const_barrett       .req v13
    mask_15             .req v14
    const_43            .req v15

    h_data0         .req v31
    h_data1         .req v30
    h_data2         .req v29
    h_data3         .req v28
    q_h_data0       .req q31
    q_h_data1       .req q30
    q_h_data2       .req q29
    q_h_data3       .req q28

CRYPT_AARCH64_FUNC_START(Usehint32)
Usehint32:
    AARCH64_PACIASP
    push_stack

    movz wtmp, #57345
    movk wtmp, #127, lsl #16
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

    movi mask_15.4s, #15

    MOV count, #(256 / 4 / 4)

.loop_32:
    load_data

    finit data0
    finit data1
    finit data2
    finit data3

    use_hint32 out0, data0, h_data0
    use_hint32 out1, data1, h_data1
    use_hint32 out2, data2, h_data2
    use_hint32 out3, data3, h_data3

    save_data

    subs count, count, #1
    cbnz count, .loop_32

    pop_stack
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(Usehint32)

CRYPT_AARCH64_FUNC_START(Usehint88)
Usehint88:
    AARCH64_PACIASP
    push_stack

    movz wtmp, #57345
    movk wtmp, #127, lsl #16
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

    movi const_43.4s, #43

    MOV count, #(256 / 4 / 4)

.loop_88:
    load_data

    finit data0
    finit data1
    finit data2
    finit data3

    use_hint88 out0, data0, h_data0
    use_hint88 out1, data1, h_data1
    use_hint88 out2, data2, h_data2
    use_hint88 out3, data3, h_data3

    save_data

    subs count, count, #1
    cbnz count, .loop_88

    pop_stack
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(Usehint88)

    .unreq in
    .unreq h_arr
    .unreq count
    .unreq wtmp

    .unreq data0
    .unreq data1
    .unreq data2
    .unreq data3
    .unreq q_data0
    .unreq q_data1
    .unreq q_data2
    .unreq q_data3
    .unreq out0
    .unreq out1
    .unreq out2
    .unreq out3
    .unreq q_out0
    .unreq q_out1
    .unreq q_out2
    .unreq q_out3
    .unreq tmp
    .unreq tmp1

    .unreq h_data0
    .unreq h_data1
    .unreq h_data2
    .unreq h_data3
    .unreq q_h_data0
    .unreq q_h_data1
    .unreq q_h_data2
    .unreq q_h_data3

    .unreq const_q
    .unreq const_2x_gamma2
    .unreq const_q_bound
    .unreq const_barrett
    .unreq mask_15
    .unreq const_43
#endif // HITLS_CRYPTO_MLDSA
