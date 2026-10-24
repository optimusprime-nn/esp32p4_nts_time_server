#include "nts_aes_siv.h"

#include <stdbool.h>
#include <string.h>

#include "psa/crypto.h"

#define SIV_SELF_TEST_NOT_RUN   0
#define SIV_SELF_TEST_PASSED    1
#define SIV_SELF_TEST_FAILED  (-1)

static int s_self_test_state = SIV_SELF_TEST_NOT_RUN;

static esp_err_t psa_to_esp(psa_status_t status)
{
    switch (status) {
    case PSA_SUCCESS:
        return ESP_OK;

    case PSA_ERROR_NOT_SUPPORTED:
        return ESP_ERR_NOT_SUPPORTED;

    case PSA_ERROR_INVALID_ARGUMENT:
    case PSA_ERROR_INVALID_HANDLE:
        return ESP_ERR_INVALID_ARG;

    case PSA_ERROR_BUFFER_TOO_SMALL:
        return ESP_ERR_INVALID_SIZE;

    case PSA_ERROR_INSUFFICIENT_MEMORY:
    case PSA_ERROR_INSUFFICIENT_STORAGE:
        return ESP_ERR_NO_MEM;

    default:
        return ESP_FAIL;
    }
}

static void secure_zero(void *buffer,
                        size_t length)
{
    if (buffer == NULL || length == 0U) {
        return;
    }

    volatile uint8_t *ptr =
        (volatile uint8_t *)buffer;

    while (length-- > 0U) {
        *ptr++ = 0U;
    }
}

static void xor_block(uint8_t output[16],
                      const uint8_t left[16],
                      const uint8_t right[16])
{
    for (size_t i = 0; i < 16U; i++) {
        output[i] = left[i] ^ right[i];
    }
}

static void dbl_block(uint8_t output[16],
                      const uint8_t input[16])
{
    uint8_t carry = 0U;

    for (int i = 15; i >= 0; i--) {
        uint8_t next_carry =
            (uint8_t)((input[i] >> 7) & 0x01U);

        output[i] =
            (uint8_t)((input[i] << 1) | carry);

        carry = next_carry;
    }

    if (carry != 0U) {
        output[15] ^= 0x87U;
    }
}

static bool constant_time_equal(
    const uint8_t *left,
    const uint8_t *right,
    size_t length)
{
    uint8_t difference = 0U;

    for (size_t i = 0; i < length; i++) {
        difference |=
            (uint8_t)(left[i] ^ right[i]);
    }

    return difference == 0U;
}

static esp_err_t import_cmac_key(
    const uint8_t key[16],
    psa_key_id_t *key_id)
{
    if (key == NULL || key_id == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_key_attributes_t attributes =
        PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_AES);

    psa_set_key_bits(
        &attributes,
        128U);

    psa_set_key_usage_flags(
        &attributes,
        PSA_KEY_USAGE_SIGN_MESSAGE);

    psa_set_key_algorithm(
        &attributes,
        PSA_ALG_CMAC);

    psa_status_t status = psa_import_key(
        &attributes,
        key,
        16U,
        key_id);

    psa_reset_key_attributes(&attributes);

    return psa_to_esp(status);
}

static esp_err_t import_ctr_key(
    const uint8_t key[16],
    psa_key_id_t *key_id)
{
    if (key == NULL || key_id == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_key_attributes_t attributes =
        PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_AES);

    psa_set_key_bits(
        &attributes,
        128U);

    psa_set_key_usage_flags(
        &attributes,
        PSA_KEY_USAGE_ENCRYPT |
        PSA_KEY_USAGE_DECRYPT);

    psa_set_key_algorithm(
        &attributes,
        PSA_ALG_CTR);

    psa_status_t status = psa_import_key(
        &attributes,
        key,
        16U,
        key_id);

    psa_reset_key_attributes(&attributes);

    return psa_to_esp(status);
}

/*
 * CMAC over the concatenation head || tail under an already-imported key.
 * S2V's final step needs CMAC(P with its last block XORed); streaming the
 * two parts avoids copying (and heap-allocating) the whole plaintext.
 */
static esp_err_t cmac_128_parts(
    psa_key_id_t key_id,
    const uint8_t *head,
    size_t head_len,
    const uint8_t *tail,
    size_t tail_len,
    uint8_t output[16])
{
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    size_t mac_len = 0U;

    psa_status_t status = psa_mac_sign_setup(
        &operation,
        key_id,
        PSA_ALG_CMAC);

    if (status == PSA_SUCCESS && head_len > 0U) {
        status = psa_mac_update(&operation, head, head_len);
    }

    if (status == PSA_SUCCESS && tail_len > 0U) {
        status = psa_mac_update(&operation, tail, tail_len);
    }

    if (status == PSA_SUCCESS) {
        status = psa_mac_sign_finish(
            &operation,
            output,
            16U,
            &mac_len);
    }

    (void)psa_mac_abort(&operation);

    if (status != PSA_SUCCESS) {
        secure_zero(output, 16U);
        return psa_to_esp(status);
    }

    if (mac_len != 16U) {
        secure_zero(output, 16U);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t cmac_128(
    psa_key_id_t key_id,
    const uint8_t *input,
    size_t input_len,
    uint8_t output[16])
{
    return cmac_128_parts(key_id, input, input_len, NULL, 0U, output);
}

static esp_err_t aes_ctr_crypt(
    const uint8_t ctr_key[16],
    const uint8_t siv[16],
    const uint8_t *input,
    size_t input_len,
    uint8_t *output)
{
    if (ctr_key == NULL ||
        siv == NULL ||
        output == NULL ||
        (input == NULL && input_len > 0U)) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_key_id_t key_id = 0U;

    esp_err_t err = import_ctr_key(
        ctr_key,
        &key_id);

    if (err != ESP_OK) {
        return err;
    }

    uint8_t iv[16];
    memcpy(iv, siv, sizeof(iv));

    /*
     * RFC 5297 CTR IV processing:
     * clear the relevant counter bits.
     */
    iv[8] &= 0x7FU;
    iv[12] &= 0x7FU;

    psa_cipher_operation_t operation =
        PSA_CIPHER_OPERATION_INIT;

    psa_status_t status = psa_cipher_encrypt_setup(
        &operation,
        key_id,
        PSA_ALG_CTR);

    if (status == PSA_SUCCESS) {
        status = psa_cipher_set_iv(
            &operation,
            iv,
            sizeof(iv));
    }

    size_t output_len = 0U;

    if (status == PSA_SUCCESS) {
        status = psa_cipher_update(
            &operation,
            input,
            input_len,
            output,
            input_len,
            &output_len);
    }

    size_t finish_len = 0U;

    if (status == PSA_SUCCESS) {
        status = psa_cipher_finish(
            &operation,
            output + output_len,
            input_len - output_len,
            &finish_len);
    }

    psa_cipher_abort(&operation);

    (void)psa_destroy_key(key_id);

    secure_zero(iv, sizeof(iv));

    if (status != PSA_SUCCESS) {
        return psa_to_esp(status);
    }

    if ((output_len + finish_len) != input_len) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t aes_siv_s2v_with_key(
    psa_key_id_t cmac_key,
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t nonce[NTS_AES_SIV_NONCE_LEN],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t tag[16])
{
    static const uint8_t zero_block[16] = {0};

    uint8_t d[16];
    uint8_t tmp[16];
    uint8_t cmac_value[16];

    esp_err_t err = cmac_128(
        cmac_key,
        zero_block,
        sizeof(zero_block),
        d);

    if (err != ESP_OK) {
        return err;
    }

    /*
     * S2V associated-data input one:
     * authenticated NTP packet bytes.
     */
    if (associated_data != NULL &&
        associated_data_len > 0U) {
        err = cmac_128(
            cmac_key,
            associated_data,
            associated_data_len,
            cmac_value);

        if (err != ESP_OK) {
            secure_zero(d, sizeof(d));
            return err;
        }

        dbl_block(tmp, d);
        xor_block(d, tmp, cmac_value);
    }

    /*
     * S2V associated-data input two:
     * NTS nonce.
     */
    if (nonce != NULL) {
        err = cmac_128(
            cmac_key,
            nonce,
            NTS_AES_SIV_NONCE_LEN,
            cmac_value);

        if (err != ESP_OK) {
            secure_zero(d, sizeof(d));
            secure_zero(tmp, sizeof(tmp));
            secure_zero(cmac_value,
                        sizeof(cmac_value));

            return err;
        }

        dbl_block(tmp, d);
        xor_block(d, tmp, cmac_value);
    }

    if (plaintext_len >= 16U) {
        /* T = P xorend D: only the final 16 bytes change, so MAC the
         * untouched prefix directly and the modified last block from the
         * stack. */
        uint8_t last_block[16];

        xor_block(last_block,
                  &plaintext[plaintext_len - 16U],
                  d);

        err = cmac_128_parts(
            cmac_key,
            plaintext,
            plaintext_len - 16U,
            last_block,
            sizeof(last_block),
            tag);

        secure_zero(last_block, sizeof(last_block));
    } else {
        uint8_t padded[16] = {0};

        if (plaintext != NULL &&
            plaintext_len > 0U) {
            memcpy(padded,
                   plaintext,
                   plaintext_len);
        }

        padded[plaintext_len] = 0x80U;

        dbl_block(tmp, d);
        xor_block(padded, padded, tmp);

        err = cmac_128(
            cmac_key,
            padded,
            sizeof(padded),
            tag);

        secure_zero(padded, sizeof(padded));
    }

    secure_zero(d, sizeof(d));
    secure_zero(tmp, sizeof(tmp));
    secure_zero(cmac_value, sizeof(cmac_value));

    return err;
}

/* One key import serves every CMAC in the S2V chain (previously one import
 * and key schedule per CMAC). */
static esp_err_t aes_siv_s2v(
    const uint8_t cmac_key[16],
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t nonce[NTS_AES_SIV_NONCE_LEN],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t tag[16])
{
    psa_key_id_t key_id = 0U;

    esp_err_t err = import_cmac_key(
        cmac_key,
        &key_id);

    if (err != ESP_OK) {
        return err;
    }

    err = aes_siv_s2v_with_key(
        key_id,
        associated_data,
        associated_data_len,
        nonce,
        plaintext,
        plaintext_len,
        tag);

    (void)psa_destroy_key(key_id);

    return err;
}

esp_err_t nts_aes_siv_init(void)
{
    return psa_to_esp(psa_crypto_init());
}

/* Known-answer test vector: key, associated data and nonce are generated
 * from simple formulas so only the expected output needs storing. Expected
 * values were produced with an independent AES-SIV implementation (Python
 * cryptography AESSIV, which also reproduces RFC 5297 A.1). */
static esp_err_t run_kat(const uint8_t key[NTS_AES_SIV_KEY_LEN],
                         const uint8_t *ad,
                         size_t ad_len,
                         const uint8_t *nonce,
                         const uint8_t *pt,
                         size_t pt_len,
                         const uint8_t *expected,
                         size_t expected_len)
{
    uint8_t out[NTS_AES_SIV_TAG_LEN + 64U];
    uint8_t back[64U];
    size_t out_len = sizeof(out);
    size_t back_len = sizeof(back);

    if (expected_len > sizeof(out) || pt_len > sizeof(back)) {
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = nts_aes_siv_encrypt(key, ad, ad_len, nonce,
                                        pt, pt_len, out, &out_len);
    if (err != ESP_OK) {
        return err;
    }

    if (out_len != expected_len ||
        memcmp(out, expected, expected_len) != 0) {
        return ESP_ERR_INVALID_CRC;
    }

    err = nts_aes_siv_decrypt(key, ad, ad_len, nonce,
                              out, out_len, back, &back_len);
    if (err != ESP_OK || back_len != pt_len ||
        (pt_len > 0U && memcmp(back, pt, pt_len) != 0)) {
        return ESP_ERR_INVALID_CRC;
    }

    /* A single flipped tag bit must be rejected. */
    out[0] ^= 0x01U;
    back_len = sizeof(back);
    err = nts_aes_siv_decrypt(key, ad, ad_len, nonce,
                              out, out_len, back, &back_len);
    secure_zero(out, sizeof(out));
    secure_zero(back, sizeof(back));
    return err == ESP_ERR_INVALID_CRC ? ESP_OK : ESP_ERR_INVALID_CRC;
}

static esp_err_t self_test_vectors(void)
{
    /* RFC 5297 Appendix A.1 (one AD component, no nonce, short plaintext). */
    static const uint8_t a1_key[32] = {
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };
    static const uint8_t a1_ad[24] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    };
    static const uint8_t a1_pt[14] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
    };
    static const uint8_t a1_out[30] = {
        0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
        0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93,
        0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04,
        0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c,
    };

    /* NTS layout (AD, nonce, plaintext) with a multi-block plaintext:
     * exercises the xorend path. */
    static const uint8_t v2_out[63] = {
        0x30, 0x85, 0xe9, 0x12, 0x72, 0x4c, 0x0e, 0xda,
        0x8c, 0x03, 0xb5, 0x78, 0x24, 0xe3, 0x82, 0xc4,
        0xa1, 0xcb, 0xa1, 0x78, 0x4d, 0xcc, 0xad, 0x78,
        0x40, 0x4b, 0xa3, 0x8e, 0x32, 0xea, 0x04, 0x7b,
        0x82, 0x48, 0xaf, 0x58, 0xe4, 0x08, 0xec, 0x55,
        0x85, 0x6a, 0xae, 0x3a, 0xc3, 0x63, 0x94, 0x87,
        0xc5, 0x54, 0x76, 0x6c, 0x68, 0xfb, 0x38, 0xb3,
        0xf6, 0x07, 0x25, 0x90, 0xec, 0xe0, 0x58,
    };

    /* NTS client-request shape: AD and nonce, empty plaintext. */
    static const uint8_t v3_out[16] = {
        0x1a, 0xec, 0x0f, 0x13, 0xe1, 0x1a, 0x8f, 0xe8,
        0x88, 0xa5, 0x6f, 0xe2, 0x5e, 0xdc, 0x4a, 0xa6,
    };

    esp_err_t err = nts_aes_siv_init();
    if (err != ESP_OK) {
        return err;
    }

    err = run_kat(a1_key, a1_ad, sizeof(a1_ad), NULL,
                  a1_pt, sizeof(a1_pt), a1_out, sizeof(a1_out));
    if (err != ESP_OK) {
        return err;
    }

    uint8_t key[32];
    uint8_t ad[64];
    uint8_t nonce[16];
    uint8_t pt[47];

    for (size_t i = 0U; i < sizeof(key); i++) {
        key[i] = (uint8_t)i;
    }
    for (size_t i = 0U; i < sizeof(ad); i++) {
        ad[i] = (uint8_t)(i * 7U + 3U);
    }
    for (size_t i = 0U; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0xa0U + i);
    }
    for (size_t i = 0U; i < sizeof(pt); i++) {
        pt[i] = (uint8_t)(i * 13U + 1U);
    }

    err = run_kat(key, ad, 64U, nonce, pt, sizeof(pt),
                  v2_out, sizeof(v2_out));
    if (err != ESP_OK) {
        return err;
    }

    for (size_t i = 0U; i < 48U; i++) {
        ad[i] = (uint8_t)(i * 5U + 9U);
    }
    for (size_t i = 0U; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0x30U + i);
    }

    return run_kat(key, ad, 48U, nonce, NULL, 0U,
                   v3_out, sizeof(v3_out));
}

esp_err_t nts_aes_siv_self_test(void)
{
    const esp_err_t err = self_test_vectors();

    /* A failed self-test permanently disables AES-SIV for this boot: NTS
     * must fail closed rather than issue or accept cookies from a broken
     * primitive. */
    __atomic_store_n(&s_self_test_state,
                     err == ESP_OK ? SIV_SELF_TEST_PASSED
                                   : SIV_SELF_TEST_FAILED,
                     __ATOMIC_RELEASE);
    return err;
}

static bool siv_disabled(void)
{
    return __atomic_load_n(&s_self_test_state, __ATOMIC_ACQUIRE) ==
           SIV_SELF_TEST_FAILED;
}

esp_err_t nts_aes_siv_encrypt(
    const uint8_t key[NTS_AES_SIV_KEY_LEN],
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t nonce[NTS_AES_SIV_NONCE_LEN],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *output,
    size_t *output_len)
{
    if (key == NULL ||
        output == NULL ||
        output_len == NULL ||
        (plaintext == NULL && plaintext_len > 0U)) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t required_len =
        NTS_AES_SIV_TAG_LEN + plaintext_len;

    if (*output_len < required_len) {
        *output_len = required_len;
        return ESP_ERR_INVALID_SIZE;
    }

    if (siv_disabled()) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    esp_err_t err = nts_aes_siv_init();

    if (err != ESP_OK) {
        return err;
    }

    uint8_t tag[16];

    err = aes_siv_s2v(
        key,
        associated_data,
        associated_data_len,
        nonce,
        plaintext,
        plaintext_len,
        tag);

    if (err != ESP_OK) {
        secure_zero(tag, sizeof(tag));
        return err;
    }

    memcpy(output, tag, NTS_AES_SIV_TAG_LEN);

    err = aes_ctr_crypt(
        &key[16],
        tag,
        plaintext,
        plaintext_len,
        &output[NTS_AES_SIV_TAG_LEN]);

    secure_zero(tag, sizeof(tag));

    if (err != ESP_OK) {
        secure_zero(output, required_len);
        return err;
    }

    *output_len = required_len;

    return ESP_OK;
}

esp_err_t nts_aes_siv_decrypt(
    const uint8_t key[NTS_AES_SIV_KEY_LEN],
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t nonce[NTS_AES_SIV_NONCE_LEN],
    const uint8_t *input,
    size_t input_len,
    uint8_t *plaintext,
    size_t *plaintext_len)
{
    if (key == NULL ||
        input == NULL ||
        plaintext == NULL ||
        plaintext_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (input_len < NTS_AES_SIV_TAG_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t ciphertext_len =
        input_len - NTS_AES_SIV_TAG_LEN;

    if (*plaintext_len < ciphertext_len) {
        *plaintext_len = ciphertext_len;
        return ESP_ERR_INVALID_SIZE;
    }

    if (siv_disabled()) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    esp_err_t err = nts_aes_siv_init();

    if (err != ESP_OK) {
        return err;
    }

    const uint8_t *received_tag = input;

    const uint8_t *ciphertext =
        &input[NTS_AES_SIV_TAG_LEN];

    err = aes_ctr_crypt(
        &key[16],
        received_tag,
        ciphertext,
        ciphertext_len,
        plaintext);

    if (err != ESP_OK) {
        secure_zero(plaintext, ciphertext_len);
        return err;
    }

    uint8_t expected_tag[16];

    err = aes_siv_s2v(
        key,
        associated_data,
        associated_data_len,
        nonce,
        plaintext,
        ciphertext_len,
        expected_tag);

    if (err != ESP_OK) {
        secure_zero(plaintext, ciphertext_len);
        secure_zero(expected_tag,
                    sizeof(expected_tag));

        return err;
    }

    bool valid = constant_time_equal(
        received_tag,
        expected_tag,
        sizeof(expected_tag));

    secure_zero(expected_tag,
                sizeof(expected_tag));

    if (!valid) {
        secure_zero(plaintext, ciphertext_len);
        return ESP_ERR_INVALID_CRC;
    }

    *plaintext_len = ciphertext_len;

    return ESP_OK;
}