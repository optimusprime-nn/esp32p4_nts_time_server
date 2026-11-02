/*
 * Unity tests for the AEAD_AES_SIV_CMAC_256 implementation in
 * main/nts_aes_siv.c.
 *
 * Build and run with the test app in test/nts_aes_siv_test_app (see its
 * README). The known-answer vectors themselves live in
 * nts_aes_siv_self_test(), which the firmware also runs at every NTS-KE
 * start; these tests cover that path plus edge cases the self-test does not.
 */
#include <string.h>

#include "unity.h"

#include "nts_aes_siv.h"

static void fill_pattern(uint8_t *buffer, size_t length, uint8_t mul, uint8_t add)
{
    for (size_t i = 0U; i < length; i++) {
        buffer[i] = (uint8_t)(i * mul + add);
    }
}

TEST_CASE("AES-SIV known-answer vectors (RFC 5297 A.1 and NTS shapes)", "[nts_aes_siv]")
{
    TEST_ASSERT_EQUAL(ESP_OK, nts_aes_siv_self_test());
}

TEST_CASE("AES-SIV round trip at NTS cookie size", "[nts_aes_siv]")
{
    /* A cookie's plaintext is 124 bytes: 4 x (16-byte block) + a partial
     * final block, exercising the xorend path with an unaligned length. */
    uint8_t key[NTS_AES_SIV_KEY_LEN];
    uint8_t ad[4];
    uint8_t nonce[NTS_AES_SIV_NONCE_LEN];
    uint8_t plaintext[124];
    uint8_t sealed[NTS_AES_SIV_TAG_LEN + sizeof(plaintext)];
    uint8_t opened[sizeof(plaintext)];

    fill_pattern(key, sizeof(key), 3U, 11U);
    fill_pattern(ad, sizeof(ad), 1U, 0x40U);
    fill_pattern(nonce, sizeof(nonce), 5U, 7U);
    fill_pattern(plaintext, sizeof(plaintext), 13U, 1U);

    size_t sealed_len = sizeof(sealed);
    TEST_ASSERT_EQUAL(ESP_OK, nts_aes_siv_encrypt(key, ad, sizeof(ad), nonce,
                                                  plaintext, sizeof(plaintext),
                                                  sealed, &sealed_len));
    TEST_ASSERT_EQUAL(sizeof(sealed), sealed_len);
    /* SIV must not leave the plaintext visible in the ciphertext. */
    TEST_ASSERT_NOT_EQUAL(0, memcmp(&sealed[NTS_AES_SIV_TAG_LEN], plaintext, sizeof(plaintext)));

    size_t opened_len = sizeof(opened);
    TEST_ASSERT_EQUAL(ESP_OK, nts_aes_siv_decrypt(key, ad, sizeof(ad), nonce,
                                                  sealed, sealed_len,
                                                  opened, &opened_len));
    TEST_ASSERT_EQUAL(sizeof(plaintext), opened_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(plaintext, opened, sizeof(plaintext));
}

TEST_CASE("AES-SIV rejects tampered associated data, nonce and ciphertext", "[nts_aes_siv]")
{
    uint8_t key[NTS_AES_SIV_KEY_LEN];
    uint8_t ad[48];
    uint8_t nonce[NTS_AES_SIV_NONCE_LEN];
    uint8_t plaintext[40];
    uint8_t sealed[NTS_AES_SIV_TAG_LEN + sizeof(plaintext)];
    uint8_t opened[sizeof(plaintext)];

    fill_pattern(key, sizeof(key), 7U, 1U);
    fill_pattern(ad, sizeof(ad), 9U, 2U);
    fill_pattern(nonce, sizeof(nonce), 11U, 3U);
    fill_pattern(plaintext, sizeof(plaintext), 17U, 4U);

    size_t sealed_len = sizeof(sealed);
    TEST_ASSERT_EQUAL(ESP_OK, nts_aes_siv_encrypt(key, ad, sizeof(ad), nonce,
                                                  plaintext, sizeof(plaintext),
                                                  sealed, &sealed_len));

    size_t opened_len = sizeof(opened);
    ad[47] ^= 0x01U;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_CRC,
                      nts_aes_siv_decrypt(key, ad, sizeof(ad), nonce,
                                          sealed, sealed_len, opened, &opened_len));
    ad[47] ^= 0x01U;

    opened_len = sizeof(opened);
    nonce[0] ^= 0x80U;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_CRC,
                      nts_aes_siv_decrypt(key, ad, sizeof(ad), nonce,
                                          sealed, sealed_len, opened, &opened_len));
    nonce[0] ^= 0x80U;

    opened_len = sizeof(opened);
    sealed[sealed_len - 1U] ^= 0x01U;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_CRC,
                      nts_aes_siv_decrypt(key, ad, sizeof(ad), nonce,
                                          sealed, sealed_len, opened, &opened_len));
    /* A failed open must not leave plaintext behind. */
    uint8_t zeros[sizeof(opened)] = {0};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(zeros, opened, sizeof(opened));
}

TEST_CASE("AES-SIV size and argument checks", "[nts_aes_siv]")
{
    uint8_t key[NTS_AES_SIV_KEY_LEN] = {0};
    uint8_t nonce[NTS_AES_SIV_NONCE_LEN] = {0};
    uint8_t plaintext[20] = {0};
    uint8_t out[NTS_AES_SIV_TAG_LEN + sizeof(plaintext)];

    /* Output buffer one byte short: reports the size it needs. */
    size_t out_len = sizeof(out) - 1U;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE,
                      nts_aes_siv_encrypt(key, NULL, 0U, nonce, plaintext,
                                          sizeof(plaintext), out, &out_len));
    TEST_ASSERT_EQUAL(sizeof(out), out_len);

    /* Input shorter than a tag cannot be valid. */
    size_t opened_len = sizeof(plaintext);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE,
                      nts_aes_siv_decrypt(key, NULL, 0U, nonce, out,
                                          NTS_AES_SIV_TAG_LEN - 1U,
                                          plaintext, &opened_len));

    out_len = sizeof(out);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                      nts_aes_siv_encrypt(NULL, NULL, 0U, nonce, plaintext,
                                          sizeof(plaintext), out, &out_len));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                      nts_aes_siv_encrypt(key, NULL, 0U, nonce, NULL,
                                          sizeof(plaintext), out, &out_len));
}

TEST_CASE("AES-SIV empty plaintext (NTS client request shape)", "[nts_aes_siv]")
{
    uint8_t key[NTS_AES_SIV_KEY_LEN];
    uint8_t ad[48];
    uint8_t nonce[NTS_AES_SIV_NONCE_LEN];
    uint8_t tag[NTS_AES_SIV_TAG_LEN];
    uint8_t unused[1];

    fill_pattern(key, sizeof(key), 1U, 0U);
    fill_pattern(ad, sizeof(ad), 5U, 9U);
    fill_pattern(nonce, sizeof(nonce), 1U, 0x30U);

    size_t tag_len = sizeof(tag);
    TEST_ASSERT_EQUAL(ESP_OK, nts_aes_siv_encrypt(key, ad, sizeof(ad), nonce,
                                                  NULL, 0U, tag, &tag_len));
    TEST_ASSERT_EQUAL(NTS_AES_SIV_TAG_LEN, tag_len);

    size_t opened_len = sizeof(unused);
    TEST_ASSERT_EQUAL(ESP_OK, nts_aes_siv_decrypt(key, ad, sizeof(ad), nonce,
                                                  tag, tag_len, unused, &opened_len));
    TEST_ASSERT_EQUAL(0, opened_len);
}
