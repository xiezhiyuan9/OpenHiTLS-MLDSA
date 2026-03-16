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

.macro mulmodq out, delta, zeta_zeta_tw, idx0, idx1
    // out = delta * zeta - round(2*delta*twisted)/2^32 * Q
    // tmp = round(2*delta*zeta)/2^32
    sqrdmulh tmp0.4s, \delta\().4s, \zeta_zeta_tw\().s[\idx1\()]
    // out = delta * zeta
    mul \out\().4s, \delta\().4s, \zeta_zeta_tw\().s[\idx0\()]
    // out = delta * zeta - round(2*delta*twisted)/2^32 * Q
    mls \out\().4s, tmp0.4s, const_q.s[0]
.endm

.macro mulmod out, delta, zeta, zeta_tw
    // out = delta * zeta - round(2*delta*twisted)/2^32 * Q
    sqrdmulh tmp0.4s, \delta\().4s, \zeta_tw\().4s
    mul \out\().4s, \delta\().4s, \zeta\().4s
    mls \out\().4s, tmp0.4s, const_q.s[0]
.endm

.macro backword_butterfly a, b, zeta_zeta_tw, idx0, idx1
    // a' = a + b, b' = barmul(a - b, zeta)
    sub tmp3.4s, \a\().4s, \b\().4s
    add \a\().4s, \a\().4s, \b\().4s
    mulmodq \b, tmp3, \zeta_zeta_tw, \idx0, \idx1
.endm

.macro backword_butterfly_v a, b, zeta, zeta_twisted
    // a' = a + b, b' = barmul(a - b, zeta)
    sub tmp3.4s, \a\().4s, \b\().4s
    add \a\().4s, \a\().4s, \b\().4s
    mulmod \b, tmp3, \zeta, \zeta_twisted
.endm

.macro mul_ninv dstmp0, dstmp1, dstmp2, dstmp3, src0, src1, src2, src3
    // Scale by 1/256*R via Barrett multiplication
    mulmod \dstmp0, \src0, ninv, ninv_tw
    mulmod \dstmp1, \src1, ninv, ninv_tw
    mulmod \dstmp2, \src2, ninv, ninv_tw
    mulmod \dstmp3, \src3, ninv, ninv_tw
.endm

.macro load_zetas_1234_bit_1_15
    ldr q_zeta1, [r123456_ptr, #(1*16)]
    ldr q_zeta2, [r123456_ptr, #(2*16)]
    ldr q_zeta3, [r123456_ptr, #(3*16)]
    ldr q_zeta4, [r123456_ptr, #(4*16)]
    ldr q_zeta5, [r123456_ptr, #(5*16)]
    ldr q_zeta6, [r123456_ptr, #(6*16)]
    ldr q_zeta7, [r123456_ptr, #(7*16)]
    ldr q_zeta0, [r123456_ptr], #(8*16)
.endm

.macro load_next_zetas_56_bit_16_31
    ldr q_zeta0, [r123456_ptr, #16]
    ldr d_zeta1, [r123456_ptr], #32
.endm

.macro load_next_zetas_78_bit_64_255
    ldr q_zeta0_tw, [r78_ptr, #(1*16)]
    ldr q_zeta1,    [r78_ptr, #(2*16)]
    ldr q_zeta1_tw, [r78_ptr, #(3*16)]
    ldr q_zeta2,    [r78_ptr, #(4*16)]
    ldr q_zeta2_tw, [r78_ptr, #(5*16)]
    ldr q_zeta0,    [r78_ptr], #(6*16)
.endm

.macro transpose4 data0, data1, data2, data3
    trn1 tmp0.4s, \data0\().4s, \data1\().4s
    trn2 tmp1.4s, \data0\().4s, \data1\().4s
    trn1 tmp2.4s, \data2\().4s, \data3\().4s
    trn2 tmp3.4s, \data2\().4s, \data3\().4s

    trn2 \data2\().2d, tmp0.2d, tmp2.2d
    trn2 \data3\().2d, tmp1.2d, tmp3.2d
    trn1 \data0\().2d, tmp0.2d, tmp2.2d
    trn1 \data1\().2d, tmp1.2d, tmp3.2d
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
    r78_ptr     .req x1
    r123456_ptr .req x2

    inp     .req x3
    count   .req x4
    wtmp    .req w5

    zeta0    .req v0
    zeta1    .req v1
    zeta2    .req v2
    zeta3    .req v3
    zeta4    .req v4
    zeta5    .req v5
    zeta6    .req v6
    zeta7    .req v7
    zeta0_tw .req v4
    zeta1_tw .req v5
    zeta2_tw .req v6
    zeta3_tw .req v7
    d_zeta1    .req d1
    q_zeta0    .req q0
    q_zeta1    .req q1
    q_zeta2    .req q2
    q_zeta3    .req q3
    q_zeta4    .req q4
    q_zeta5    .req q5
    q_zeta6    .req q6
    q_zeta7    .req q7
    q_zeta0_tw .req q4
    q_zeta1_tw .req q5
    q_zeta2_tw .req q6
    q_zeta3_tw .req q7

    data0  .req v8
    data1  .req v9
    data2  .req v10
    data3  .req v11
    data4  .req v12
    data5  .req v13
    data6  .req v14
    data7  .req v15
    data8  .req v16
    data9  .req v17
    data10 .req v18
    data11 .req v19
    data12 .req v20
    data13 .req v21
    data14 .req v22
    data15 .req v23

    q_data0  .req q8
    q_data1  .req q9
    q_data2  .req q10
    q_data3  .req q11
    q_data4  .req q12
    q_data5  .req q13
    q_data6  .req q14
    q_data7  .req q15
    q_data8  .req q16
    q_data9  .req q17
    q_data10 .req q18
    q_data11 .req q19
    q_data12 .req q20
    q_data13 .req q21
    q_data14 .req q22
    q_data15 .req q23

    const_q     .req v31
    ninv_tw     .req v30
    ninv        .req v29
    tmp0        .req v28
    tmp1        .req v27
    tmp2        .req v26
    tmp3        .req v25

CRYPT_AARCH64_FUNC_START(MldsaInttAsm)
MldsaInttAsm:
    AARCH64_PACIASP
    push_stack

    // Load MLDSA_Q = 8380417
    movz wtmp, #0xe001
    movk wtmp, #0x7f, lsl #16
    dup const_q.4s, wtmp

    mov inp, in
    mov count, #16

    .p2align 2

.intt_layer5678_start:

    ldr q_data0, [inp, #(16*0)]
    ldr q_data1, [inp, #(16*1)]
    ldr q_data2, [inp, #(16*2)]
    ldr q_data3, [inp, #(16*3)]

    // 4x4 matrix transpose for d0 d1 d2 d3
    transpose4 data0, data1, data2, data3

    load_next_zetas_78_bit_64_255
    // layer 8, bit [127~134:256:8], zeta2[8~23:384:24]
    // arr [0 4 8 12] x [1 5 9 13] d = 1
    backword_butterfly_v data0, data1, zeta1, zeta1_tw
    backword_butterfly_v data2, data3, zeta2, zeta2_tw

    // layer 7, bit [64~71:128:4], zeta2[0~7:384:24]
    // arr [0 4 8 12] x [2 6 10 14] d = 2
    backword_butterfly_v data0, data2, zeta0, zeta0_tw
    backword_butterfly_v data1, data3, zeta0, zeta0_tw

    // [0123][4567]...
    transpose4 data0, data1, data2, data3

    load_next_zetas_56_bit_16_31

    // Layer 6, bit [32~33:64:2], zeta[4~7:128:8]
    // arr [0 1 2 3] x [4 5 6 7] d = 4
    backword_butterfly data0, data1, zeta0, 0, 1
    backword_butterfly data2, data3, zeta0, 2, 3

    // Layer 5, bit [16:32:1], zeta[0~1:128:8]
    // [0 1 2 3] x [8 9 10 11] d = 8
    backword_butterfly data0, data2, zeta1, 0, 1
    backword_butterfly data1, data3, zeta1, 0, 1

    str q_data0, [inp], #(64)
    str q_data1, [inp, #(-64 + 16*1)]
    str q_data2, [inp, #(-64 + 16*2)]
    str q_data3, [inp, #(-64 + 16*3)]

    subs count, count, #1
    cbnz count, .intt_layer5678_start

    // ---------------------------------------------------------------------

    /* check-magic: 16382 == pow(2, 32-8, MLDSA_Q) */
    // Load scaling factor 1/256*R
    mov wtmp, #16382 // 2^(32 - 8) mod Q
    dup ninv.4s, wtmp

    /* check-magic: 4197891 == round(16382 * 2**31 / MLDSA_Q) */
    // Load Barrett constant for 1/256*R
    movz wtmp, #0x0e03
    movk wtmp, #0x40, lsl #16
    dup ninv_tw.4s, wtmp

    mov count, #4
    load_zetas_1234_bit_1_15

    .p2align 2

.intt_layer1234_start:

    ldr q_data0,  [in, #0]                  // [ 0  1  2  3]
    ldr q_data1,  [in, #(1*(512/8))]        // [16 17 18 19]
    ldr q_data2,  [in, #(2*(512/8))]        // [32 33 34 35]
    ldr q_data3,  [in, #(3*(512/8))]        // [64 65 66 67]
    ldr q_data4,  [in, #(4*(512/8))]
    ldr q_data5,  [in, #(5*(512/8))]
    ldr q_data6,  [in, #(6*(512/8))]
    ldr q_data7,  [in, #(7*(512/8))]
    ldr q_data8,  [in, #(8*(512/8))]        // [128 129 130 131]
    ldr q_data9,  [in, #(9*(512/8))]
    ldr q_data10, [in, #(10*(512/8))]
    ldr q_data11, [in, #(11*(512/8))]
    ldr q_data12, [in, #(12*(512/8))]
    ldr q_data13, [in, #(13*(512/8))]
    ldr q_data14, [in, #(14*(512/8))]
    ldr q_data15, [in, #(15*(512/8))]

    // Layer 4, bit [8~15], zeta[142~157]
    // [ 0  1  2  3] x [16 17 18 19], d = 16
    backword_butterfly data0, data1, zeta3, 2, 3
    backword_butterfly data2, data3, zeta4, 0, 1
    backword_butterfly data4, data5, zeta4, 2, 3
    backword_butterfly data6, data7, zeta5, 0, 1
    backword_butterfly data8, data9, zeta5, 2, 3
    backword_butterfly data10, data11, zeta6, 0, 1
    backword_butterfly data12, data13, zeta6, 2, 3
    backword_butterfly data14, data15, zeta7, 0, 1

    // Layer 3, bit [4~7], zeta[134~141]
    // [ 0  1  2  3] x [32 33 34 35], d = 32
    backword_butterfly data0, data2, zeta1, 2, 3
    backword_butterfly data1, data3, zeta1, 2, 3
    backword_butterfly data4, data6, zeta2, 0, 1
    backword_butterfly data5, data7, zeta2, 0, 1
    backword_butterfly data8, data10, zeta2, 2, 3
    backword_butterfly data9, data11, zeta2, 2, 3
    backword_butterfly data12, data14, zeta3, 0, 1
    backword_butterfly data13, data15, zeta3, 0, 1

    // Layer 2, bit [2, 3], zeta[130~133]
    // [ 0  1  2  3] x [64 65 66 67], d = 64
    backword_butterfly data0, data4, zeta0, 2, 3
    backword_butterfly data1, data5, zeta0, 2, 3
    backword_butterfly data2, data6, zeta0, 2, 3
    backword_butterfly data3, data7, zeta0, 2, 3
    backword_butterfly data8, data12, zeta1, 0, 1
    backword_butterfly data9, data13, zeta1, 0, 1
    backword_butterfly data10, data14, zeta1, 0, 1
    backword_butterfly data11, data15, zeta1, 0, 1

    // Layer 1, bit 1, zeta[128~129]
    // [ 0  1  2  3] x [128 129 130 131], d = 128
    backword_butterfly data0, data8, zeta0, 0, 1
    backword_butterfly data1, data9, zeta0, 0, 1
    backword_butterfly data2, data10, zeta0, 0, 1
    backword_butterfly data3, data11, zeta0, 0, 1
    backword_butterfly data4, data12, zeta0, 0, 1
    backword_butterfly data5, data13, zeta0, 0, 1
    backword_butterfly data6, data14, zeta0, 0, 1
    backword_butterfly data7, data15, zeta0, 0, 1

    str q_data8, [in, #(8*(512/8))]
    str q_data9, [in, #(9*(512/8))]
    str q_data10, [in, #(10*(512/8))]
    str q_data11, [in, #(11*(512/8))]
    str q_data12, [in, #(12*(512/8))]
    str q_data13, [in, #(13*(512/8))]
    str q_data14, [in, #(14*(512/8))]
    str q_data15, [in, #(15*(512/8))]

    // Scale by 1/256*R
    mul_ninv data0, data1, data2, data3, data0, data1, data2, data3
    mul_ninv data4, data5, data6, data7, data4, data5, data6, data7

    str q_data0, [in], #(16)
    str q_data1, [in, #(-16 + 1*(512/8))]
    str q_data2, [in, #(-16 + 2*(512/8))]
    str q_data3, [in, #(-16 + 3*(512/8))]
    str q_data4, [in, #(-16 + 4*(512/8))]
    str q_data5, [in, #(-16 + 5*(512/8))]
    str q_data6, [in, #(-16 + 6*(512/8))]
    str q_data7, [in, #(-16 + 7*(512/8))]

    subs count, count, #1
    cbnz count, .intt_layer1234_start

    pop_stack
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MldsaInttAsm)

/****************** REGISTER DEALLOCATIONS *******************/
    .unreq in
    .unreq r78_ptr
    .unreq r123456_ptr
    .unreq inp
    .unreq count
    .unreq wtmp
    .unreq data0
    .unreq data1
    .unreq data2
    .unreq data3
    .unreq data4
    .unreq data5
    .unreq data6
    .unreq data7
    .unreq data8
    .unreq data9
    .unreq data10
    .unreq data11
    .unreq data12
    .unreq data13
    .unreq data14
    .unreq data15
    .unreq q_data0
    .unreq q_data1
    .unreq q_data2
    .unreq q_data3
    .unreq q_data4
    .unreq q_data5
    .unreq q_data6
    .unreq q_data7
    .unreq q_data8
    .unreq q_data9
    .unreq q_data10
    .unreq q_data11
    .unreq q_data12
    .unreq q_data13
    .unreq q_data14
    .unreq q_data15
    .unreq zeta0
    .unreq zeta1
    .unreq zeta2
    .unreq zeta3
    .unreq zeta4
    .unreq zeta5
    .unreq zeta6
    .unreq zeta7
    .unreq zeta0_tw
    .unreq zeta1_tw
    .unreq zeta2_tw
    .unreq zeta3_tw
    .unreq const_q
    .unreq q_zeta0
    .unreq q_zeta1
    .unreq q_zeta2
    .unreq q_zeta3
    .unreq q_zeta4
    .unreq q_zeta5
    .unreq q_zeta6
    .unreq q_zeta7
    .unreq q_zeta0_tw
    .unreq q_zeta1_tw
    .unreq q_zeta2_tw
    .unreq q_zeta3_tw
    .unreq d_zeta1
    .unreq tmp0
    .unreq tmp1
    .unreq tmp2
    .unreq tmp3
    .unreq ninv
    .unreq ninv_tw
#endif // HITLS_CRYPTO_MLDSA
