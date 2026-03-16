# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.


file(GLOB _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/ml_dsa.c)
list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/ml_dsa_core.c)

if(HITLS_CRYPTO_MLDSA_ARMV8)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/decompose_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/intt_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/ntt_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/pointwise_acc_montgomery_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/pointwise_montgomery_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/polyz_unpack_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/power2round_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/rej_uniform_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/rej_uniform_eta2_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/rej_uniform_eta4_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/usehint_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/validity_check_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/vec_opts_x8_armv8.S)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/export_ml_dsa_armv8.c)
else()
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/export_ml_dsa_c.c)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/ml_dsa_ntt.c)
endif()

add_library(_hitls_crypto_mldsa OBJECT ${_mldsa_sources})

if(HITLS_CRYPTO_MLDSA_ARMV8)
    target_compile_definitions(_hitls_crypto_mldsa PRIVATE HITLS_CRYPTO_MLDSA_X2)
endif()

target_link_libraries(_hitls_crypto_mldsa
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_mldsa
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
        ${PROJECT_SOURCE_DIR}/crypto/sha3/include
        ${PROJECT_SOURCE_DIR}/crypto/sha3/src
        ${PROJECT_SOURCE_DIR}/bsl/obj/include
)

hitls_register_objects(CRYPTO _hitls_crypto_mldsa)
