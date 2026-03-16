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
    ldr q_data1, [arr, #(1*(1024/8))]
    ldr q_data2, [arr, #(2*(1024/8))]
    ldr q_data3, [arr, #(3*(1024/8))]
    ldr q_data4, [arr, #(4*(1024/8))]
    ldr q_data5, [arr, #(5*(1024/8))]
    ldr q_data6, [arr, #(6*(1024/8))]
    ldr q_data7, [arr, #(7*(1024/8))]
    ldr q_data0, [arr], #16
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

.macro check_one_line ldata, lmask
    // n = z[j] >> 31;    // Shift rightwards by 31 bits.
    // n = z[j] - (n & ((uint32_t)z[j] << 1));
    // if (n >= t) return false;
    // => n = z < 0? z - z*2 : z = ABS(z); 
    // n>=t -> hit -> return 1
    ABS \ldata\().4s, \ldata\().4s
    CMGE \lmask\().4s, \ldata\().4s, const_t.4s
.endm

    output     .req w0
    arr     .req x0
    para_t  .req w1

    count     .req x4

    data0     .req v0
    data1     .req v1
    data2     .req v2
    data3     .req v3
    data4     .req v4
    data5     .req v5
    data6     .req v6
    data7     .req v7
    q_data0     .req q0
    q_data1     .req q1
    q_data2     .req q2
    q_data3     .req q3
    q_data4     .req q4
    q_data5     .req q5
    q_data6     .req q6
    q_data7     .req q7
    tmp         .req v30
    tmp1        .req v29
    mask_tmp    .req v28
    mask_final  .req v27
    const_t     .req v26

CRYPT_AARCH64_FUNC_START(ValidityCheck)
ValidityCheck:
    AARCH64_PACIASP
    dup const_t.4s, para_t

    mov count, #(256 / 32)
    eor tmp.16b, tmp.16b, tmp.16b

    .p2align 2

.check_loop:
    load_data
    check_one_line data0, mask_final

    check_one_line data1, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data2, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data3, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data4, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data5, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data6, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data7, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b

    ORR tmp.16b, tmp.16b, mask_final.16b
    subs count, count, #1
    cbnz count, .check_loop

    UMAXV s29, tmp.4s
    umov w3, v29.s[0]

done:
    mov w0, #0
    cmp w3, #0
    cset w0, eq

    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(ValidityCheck)

    .unreq output
    .unreq arr
    .unreq para_t
    .unreq count

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
    .unreq tmp
    .unreq tmp1
    .unreq mask_tmp
    .unreq mask_final
    .unreq const_t
#endif // HITLS_CRYPTO_MLDSA