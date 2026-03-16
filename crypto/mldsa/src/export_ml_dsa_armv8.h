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

#ifndef ML_DSA_ARMV8_H
#define ML_DSA_ARMV8_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @ingroup mldsa
 * @brief NTT/INTT function
 *
 * @param w [IN/OUT] 256 x int32 coefficients of the polynomial to be transformed.
 * @param zeta1 [IN] zeta table p1
 * @param zeta2 [IN] zeta table p2
 */
void MldsaNttAsm(int32_t *w, const int32_t *zeta1, const int32_t *zeta2);
void MldsaInttAsm(int32_t *w, const int32_t *zeta1, const int32_t *zeta2);

/**
 * @ingroup mldsa
 * @brief poly mul
 *
 * @param t [OUT] 256 x int32 out
 * @param a [IN] 256 x int32 a
 * @param b [IN] 256 x int32 b
 */
void PolyPointwiseMontgomeryAsm(int32_t *t, const int32_t *a, const int32_t *b);

/**
 * @ingroup mldsa
 * @brief NTT/INTT function
 *
 * @param inoutArr [IN/OUT] 256 x int32 coefficients to recover
 * @param h [IN] 256 x int32 hint mask
 */
void Usehint88(int32_t *inoutArr, const int32_t *h);
void Usehint32(int32_t *inoutArr, const int32_t *h);

/**
 * @ingroup mldsa
 * @brief decompose w into high and low parts using Power2Round
 *
 * @param inoutA0 [IN/OUT] 256 x int32 input, and lower part output
 * @param inoutA1 [OUT] 256 x int32 upper part output
 */
void BatchDecompose88(int32_t *inoutA0, int32_t *inoutA1);
void BatchDecompose32(int32_t *inoutA0, int32_t *inoutA1);

/**
 * @ingroup mldsa
 * @brief rejection sampling for uniform distribution
 *
 * @param r [OUT] 256 x int32 coefficients output
 * @param buf [IN] buffer data to generate distribution 
 * @param buflen [IN] length of the buffer
 * @param table [IN] index table for TBL SIMD selection
 */
uint64_t MldRejUniformAsm(int32_t *r, const uint8_t *buf, unsigned buflen,
    const uint8_t *table);
uint64_t MldRejUniformEta2Asm(int32_t *r, const uint8_t *buf,
    unsigned buflen, const uint8_t *table);
uint64_t MldRejUniformEta4Asm(int32_t *r, const uint8_t *buf,
    unsigned buflen, const uint8_t *table);

/**
 * @ingroup mldsa
 * @brief boundry check for coefficients, |z| < t
 *
 * @param data [IN] 256 x int32 coefficients
 * @param t [IN] boundry
 * 
 * @retval true if all coefficients are less than t, otherwise false.
 */
bool ValidityCheck(const int32_t* data, uint32_t t);

/**
 * @ingroup mldsa
 * @brief vector add/sub
 *
 * @param t [OUT] 256 x int32 coefficients output
 * @param a [IN] 256 x int32 coefficients
 * @param b [IN] 256 x int32 coefficients
 */
void VecAdd(int32_t *t, int32_t *a, int32_t *b);
void VecAddq(int32_t *t, int32_t *a, int32_t *b);
void VecSub(int32_t *t, int32_t *a, int32_t *b);

/**
 * @ingroup mldsa
 * @brief power2round, decompose into t0 (low bits) and t1 (high bits)
 *
 * @param t0 [OUT] 256 x int32 coefficients output (low bits)
 * @param t1 [IN/OUT] 256 x int32 coefficients output (high bits)
 */
void VecPower2round(int32_t *t0, int32_t *t1);

/**
 * @ingroup mldsa
 * @brief poly unpack for signature, unpack the polynomial from byte array to int32 array, and extract the sign bit
 *
 * @param r [OUT] 256 x int32 coefficients output
 * @param buf [IN] byte array input
 * @param indices [IN] index table for TBL SIMD selection
 */
void PolyzUnpack17Asm(uint32_t *r, const uint8_t *buf,
    const uint8_t *indices);
void PolyzUnpack19Asm(uint32_t *r, const uint8_t *buf,
    const uint8_t *indices);

/**
 * @ingroup mldsa
 * @brief Montgomery pointwise accumulation for verification, compute r = a * b + r, where a is in NTT domain and b is in normal domain
 *
 * @param T [OUT] 256 x int32 coefficients output
 * @param A [IN] 256 x int32 coefficients for a
 * @param B [IN] 256 x int32 coefficients for b
 */
void PolyveclPointwiseAccMontgomeryL4Asm(int32_t *t, const int32_t *a, const int32_t *b);
void PolyveclPointwiseAccMontgomeryL5Asm(int32_t *t, const int32_t *a, const int32_t *b);
void PolyveclPointwiseAccMontgomeryL7Asm(int32_t *t, const int32_t *a, const int32_t *b);

#endif /* ML_DSA_ARMV8_H */