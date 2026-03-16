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

.macro forward_butterfly a, b, zeta_zeta_tw, idx0, idx1
    // a' = a + barmul(b, zeta), b' = a - barmul(b, zeta)
    mulmodq tmp3, \b, \zeta_zeta_tw, \idx0, \idx1
    sub \b\().4s, \a\().4s, tmp3.4s
    add \a\().4s, \a\().4s, tmp3.4s
.endm

.macro forward_butterfly_v a, b, zeta, zeta_tw
    // a' = a + barmul(b, zeta), b' = a - barmul(b, zeta)
    mulmod tmp3, \b, \zeta, \zeta_tw
    sub \b\().4s, \a\().4s, tmp3.4s
    add \a\().4s, \a\().4s, tmp3.4s
.endm

.macro load_zetas_bit_1_7
    ldr q_zeta1, [r012345_ptr, #(1*16)]
    ldr q_zeta2, [r012345_ptr, #(2*16)]
    ldr q_zeta3, [r012345_ptr, #(3*16)]
    ldr q_zeta0, [r012345_ptr], #(4*16)
.endm

.macro load_zetas_456_bit_8_63
    ldr q_zeta1, [r012345_ptr, #(1*16)]
    ldr q_zeta2, [r012345_ptr, #(2*16)]
    ldr q_zeta3, [r012345_ptr, #(3*16)]
    ldr q_zeta0, [r012345_ptr], #(4*16)
.endm

.macro load_zetas_78_p1_bit_64_255
    ldr q_zeta0_tw, [r67_ptr, #(1*16)]
    ldr q_zeta1,    [r67_ptr, #(2*16)]
    ldr q_zeta1_tw, [r67_ptr, #(3*16)]
    ldr q_zeta2,    [r67_ptr, #(4*16)]
    ldr q_zeta2_tw, [r67_ptr, #(5*16)]
    ldr q_zeta0,    [r67_ptr], #(12*16)
.endm

.macro load_zetas_78_p2_bit_64_255
    ldr q_zeta0,    [r67_ptr, #(-12*16 + 6*16)]
    ldr q_zeta0_tw, [r67_ptr, #(-12*16 + 7*16)]
    ldr q_zeta1,    [r67_ptr, #(-12*16 + 8*16)]
    ldr q_zeta1_tw, [r67_ptr, #(-12*16 + 9*16)]
    ldr q_zeta2,    [r67_ptr, #(-12*16 + 10*16)]
    ldr q_zeta2_tw, [r67_ptr, #(-12*16 + 11*16)]
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

    in          .req x0  // Input/output buffer
    r012345_ptr .req x1  // twiddles for layer 0,1,2,3,4,5
    r67_ptr     .req x2  // twiddles for layer 6,7

    inp     .req x3
    count   .req x4
    wtmp    .req w5

    zeta0    .req v0
    zeta1    .req v1
    zeta2    .req v2
    zeta3    .req v3
    zeta0_tw .req v4
    zeta1_tw .req v5
    zeta2_tw .req v6

    q_zeta0    .req q0
    q_zeta1    .req q1
    q_zeta2    .req q2
    q_zeta3    .req q3
    q_zeta0_tw .req q4
    q_zeta1_tw .req q5
    q_zeta2_tw .req q6

    const_q   .req v7

    data0  .req v8
    data1  .req v9
    data2  .req v10
    data3  .req v11
    data4  .req v12
    data5  .req v13
    data6  .req v14
    data7  .req v15

    q_data0  .req q8
    q_data1  .req q9
    q_data2  .req q10
    q_data3  .req q11
    q_data4  .req q12
    q_data5  .req q13
    q_data6  .req q14
    q_data7  .req q15

    tmp0  .req v31
    tmp1  .req v30
    tmp2  .req v29
    tmp3  .req v28

CRYPT_AARCH64_FUNC_START(MldsaNttAsm)

MldsaNttAsm:
    AARCH64_PACIASP
    push_stack

    // Load MLDSA_Q = 8380417
    movz wtmp, #0xe001
    movk wtmp, #0x7f, lsl #16
    dup const_q.4s, wtmp

    mov inp, in
    mov count, #8

    load_zetas_bit_1_7

    .p2align 2

.ntt_layer123_start:

    ldr q_data0, [in]
    ldr q_data1, [in, #(1*(1024/8))]
    ldr q_data2, [in, #(2*(1024/8))]
    ldr q_data3, [in, #(3*(1024/8))]
    ldr q_data4, [in, #(4*(1024/8))]
    ldr q_data5, [in, #(5*(1024/8))]
    ldr q_data6, [in, #(6*(1024/8))]
    ldr q_data7, [in, #(7*(1024/8))]

    // layer 1, bit 1, zeta[0:2]
    forward_butterfly data0, data4, zeta0, 0, 1
    forward_butterfly data1, data5, zeta0, 0, 1
    forward_butterfly data2, data6, zeta0, 0, 1
    forward_butterfly data3, data7, zeta0, 0, 1

    // layer 2, bit 2,3, zeta[2:6]
    forward_butterfly data0, data2, zeta0, 2, 3
    forward_butterfly data1, data3, zeta0, 2, 3
    forward_butterfly data4, data6, zeta1, 0, 1
    forward_butterfly data5, data7, zeta1, 0, 1

    // layer 3, bit [4:8], zeta[6:14]
    forward_butterfly data0, data1, zeta1, 2, 3
    forward_butterfly data2, data3, zeta2, 0, 1
    forward_butterfly data4, data5, zeta2, 2, 3
    forward_butterfly data6, data7, zeta3, 0, 1

    str q_data1, [in, #(1*(1024/8))]
    str q_data2, [in, #(2*(1024/8))]
    str q_data3, [in, #(3*(1024/8))]
    str q_data4, [in, #(4*(1024/8))]
    str q_data5, [in, #(5*(1024/8))]
    str q_data6, [in, #(6*(1024/8))]
    str q_data7, [in, #(7*(1024/8))]
    str q_data0, [in], #(16)

    subs count, count, #1
    cbnz count, .ntt_layer123_start

    mov in, inp
    mov count, #8

    .p2align 2

.ntt_layer45678_start:

    ldr q_data0, [in, #(16*0)]
    ldr q_data1, [in, #(16*1)]
    ldr q_data2, [in, #(16*2)]
    ldr q_data3, [in, #(16*3)]
    ldr q_data4, [in, #(16*4)]
    ldr q_data5, [in, #(16*5)]
    ldr q_data6, [in, #(16*6)]
    ldr q_data7, [in, #(16*7)]

    load_zetas_456_bit_8_63

    // layer 4, bit [8:64:7], zeta[16~17:144:16]
    forward_butterfly data0, data4, zeta0, 0, 1
    forward_butterfly data1, data5, zeta0, 0, 1
    forward_butterfly data2, data6, zeta0, 0, 1
    forward_butterfly data3, data7, zeta0, 0, 1

    // layer 5, bit [9~10:64:7], zeta[18~21:144:16]
    forward_butterfly data0, data2, zeta0, 2, 3
    forward_butterfly data1, data3, zeta0, 2, 3
    forward_butterfly data4, data6, zeta1, 0, 1
    forward_butterfly data5, data7, zeta1, 0, 1

    // layer 6, bit [11~14:64:7], zeta[22~29:144:16]
    forward_butterfly data0, data1, zeta1, 2, 3
    forward_butterfly data2, data3, zeta2, 0, 1
    forward_butterfly data4, data5, zeta2, 2, 3
    forward_butterfly data6, data7, zeta3, 0, 1

    // 4x4 matrix transpose for d0 d1 d2 d3
    transpose4 data0, data1, data2, data3
    transpose4 data4, data5, data6, data7
        
    load_zetas_78_p1_bit_64_255

    // layer 7 p1, bit [64~67:255:24], zeta2[0~7:384:48]
    forward_butterfly_v data0, data2, zeta0, zeta0_tw
    forward_butterfly_v data1, data3, zeta0, zeta0_tw
    // layer 8 p1, bit [128~135:255:24], zeta2[8~23:384:48]
    forward_butterfly_v data0, data1, zeta1, zeta1_tw
    forward_butterfly_v data2, data3, zeta2, zeta2_tw

    load_zetas_78_p2_bit_64_255

    // layer 7 p2, bit [68~71:255:24], zeta2[24~31:384:48]
    forward_butterfly_v data4, data6, zeta0, zeta0_tw
    forward_butterfly_v data5, data7, zeta0, zeta0_tw
    // layer 8 p2, bit [136~143:255:24], zeta2[32~47:384:48]
    forward_butterfly_v data4, data5, zeta1, zeta1_tw
    forward_butterfly_v data6, data7, zeta2, zeta2_tw

    // 4x4 transpose back
    transpose4 data0, data1, data2, data3
    transpose4 data4, data5, data6, data7

    str q_data0, [in], #(16*8)
    str q_data1, [in, #(-16*7)]
    str q_data2, [in, #(-16*6)]
    str q_data3, [in, #(-16*5)]
    str q_data4, [in, #(-16*4)]
    str q_data5, [in, #(-16*3)]
    str q_data6, [in, #(-16*2)]
    str q_data7, [in, #(-16*1)]

    subs count, count, #1
    cbnz count, .ntt_layer45678_start

    pop_stack
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MldsaNttAsm)

    .unreq in
    .unreq r012345_ptr
    .unreq r67_ptr
    .unreq inp
    .unreq count
    .unreq wtmp

    .unreq zeta0
    .unreq zeta1
    .unreq zeta2
    .unreq zeta3
    .unreq zeta0_tw
    .unreq zeta1_tw
    .unreq zeta2_tw
    .unreq q_zeta0
    .unreq q_zeta1
    .unreq q_zeta2
    .unreq q_zeta3
    .unreq q_zeta0_tw
    .unreq q_zeta1_tw
    .unreq q_zeta2_tw
    .unreq const_q

    .unreq data0
    .unreq data1
    .unreq data2
    .unreq data3
    .unreq data4
    .unreq data5
    .unreq data6
    .unreq data7
    .unreq q_data0
    .unreq q_data1
    .unreq q_data2
    .unreq q_data3
    .unreq q_data4
    .unreq q_data5
    .unreq q_data6
    .unreq q_data7

    .unreq tmp0
    .unreq tmp1
    .unreq tmp2
    .unreq tmp3
#endif // HITLS_CRYPTO_MLDSA
