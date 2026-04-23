/*
 * NFC Dictionary Generator
 * Runtime generation of master key candidates
 *
 * SPDX-License-Identifier: MIT
 */

#include "dict_generator.h"
#include "nrf_log.h"
#include <string.h>
#include <stdlib.h>

// Known Amiibo master key patterns
static const struct {
    const char* type_string;
    const uint8_t hmac_key[16];
    const uint8_t magic_bytes[16];
    const uint8_t xor_pad[32];
} KNOWN_KEY_PATTERNS[] = {
    // UID0 - figure
    {
        "UID0",
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    },
};

#define KNOWN_KEY_PATTERNS_COUNT (sizeof(KNOWN_KEY_PATTERNS) / sizeof(KNOWN_KEY_PATTERNS[0]))

// Dictionary generation cache
static nfc3d_keygen_masterkeys* g_dictionary = NULL;
static uint16_t g_dictionary_size = 0;
static dict_generator_mode_t g_current_mode = DICT_GEN_MODE_BASIC;

void dict_generator_init(void)
{
    NRF_LOG_INFO("Dictionary generator initialized");
}

uint16_t dict_generator_generate(
    dict_generator_mode_t mode,
    nfc3d_keygen_masterkeys** out_dict
)
{
    if (out_dict == NULL) {
        NRF_LOG_ERROR("Invalid output pointer");
        return 0;
    }

    uint16_t count = 0;
    
    switch (mode) {
        case DICT_GEN_MODE_BASIC:
            count = dict_generator_basic(out_dict);
            break;
        case DICT_GEN_MODE_VARIATIONS:
            count = dict_generator_variations(out_dict);
            break;
        case DICT_GEN_MODE_BRUTEFORCE:
            count = dict_generator_bruteforce_lite(out_dict);
            break;
        default:
            NRF_LOG_WARNING("Unknown dictionary generation mode: %d", mode);
            return 0;
    }

    g_dictionary = *out_dict;
    g_dictionary_size = count;
    g_current_mode = mode;
    
    NRF_LOG_INFO("Generated %d keys in mode %d", count, mode);
    return count;
}

uint16_t dict_generator_basic(nfc3d_keygen_masterkeys** out_dict)
{
    // Allocate dictionary
    *out_dict = malloc(sizeof(nfc3d_keygen_masterkeys) * BASIC_DICT_SIZE);
    if (*out_dict == NULL) {
        NRF_LOG_ERROR("Failed to allocate dictionary memory");
        return 0;
    }

    uint16_t idx = 0;
    
    // Add known patterns
    for (uint16_t i = 0; i < KNOWN_KEY_PATTERNS_COUNT && idx < BASIC_DICT_SIZE; i++) {
        memcpy((*out_dict)[idx].typeString, KNOWN_KEY_PATTERNS[i].type_string, 14);
        memcpy((*out_dict)[idx].hmacKey, KNOWN_KEY_PATTERNS[i].hmac_key, 16);
        memcpy((*out_dict)[idx].magicBytes, KNOWN_KEY_PATTERNS[i].magic_bytes, 16);
        memcpy((*out_dict)[idx].xorPad, KNOWN_KEY_PATTERNS[i].xor_pad, 32);
        (*out_dict)[idx].rfu = 0;
        (*out_dict)[idx].magicBytesSize = 16;
        idx++;
    }

    // Add common zero patterns
    if (idx < BASIC_DICT_SIZE) {
        memset(&(*out_dict)[idx], 0, sizeof(nfc3d_keygen_masterkeys));
        strncpy((*out_dict)[idx].typeString, "UID0\0", 14);
        (*out_dict)[idx].magicBytesSize = 0;
        idx++;
    }

    // Add weak key patterns (all 0xFF)
    if (idx < BASIC_DICT_SIZE) {
        memset(&(*out_dict)[idx], 0xFF, sizeof(nfc3d_keygen_masterkeys));
        strncpy((*out_dict)[idx].typeString, "FFFF\0", 14);
        (*out_dict)[idx].magicBytesSize = 16;
        idx++;
    }

    NRF_LOG_INFO("Generated %d basic dictionary entries", idx);
    return idx;
}

uint16_t dict_generator_variations(nfc3d_keygen_masterkeys** out_dict)
{
    // Allocate larger dictionary for variations
    uint16_t max_entries = BASIC_DICT_SIZE + VARIATIONS_DICT_EXTRA;
    *out_dict = malloc(sizeof(nfc3d_keygen_masterkeys) * max_entries);
    if (*out_dict == NULL) {
        NRF_LOG_ERROR("Failed to allocate variations dictionary");
        return 0;
    }

    uint16_t idx = 0;

    // Start with basic patterns
    idx = dict_generator_basic(out_dict);

    // Add byte-rotated variations of first pattern
    if (idx < max_entries && KNOWN_KEY_PATTERNS_COUNT > 0) {
        for (int rotate = 1; rotate < 8 && idx < max_entries; rotate++) {
            memcpy(&(*out_dict)[idx], &KNOWN_KEY_PATTERNS[0], sizeof(nfc3d_keygen_masterkeys));
            
            // Rotate HMAC key
            uint8_t temp = (*out_dict)[idx].hmacKey[0];
            for (int i = 0; i < 15; i++) {
                (*out_dict)[idx].hmacKey[i] = (*out_dict)[idx].hmacKey[i + 1];
            }
            (*out_dict)[idx].hmacKey[15] = temp;
            
            idx++;
        }
    }

    // Add incrementally modified patterns
    if (idx < max_entries) {
        for (int inc = 1; inc < 16 && idx < max_entries; inc++) {
            memset(&(*out_dict)[idx], inc, sizeof(nfc3d_keygen_masterkeys));
            snprintf((*out_dict)[idx].typeString, 14, "INC%02X\0", inc);
            (*out_dict)[idx].magicBytesSize = 8;
            idx++;
        }
    }

    NRF_LOG_INFO("Generated %d variation dictionary entries", idx);
    return idx;
}

uint16_t dict_generator_bruteforce_lite(nfc3d_keygen_masterkeys** out_dict)
{
    // Limited brute force - common patterns only
    uint16_t max_entries = BRUTEFORCE_DICT_SIZE;
    *out_dict = malloc(sizeof(nfc3d_keygen_masterkeys) * max_entries);
    if (*out_dict == NULL) {
        NRF_LOG_ERROR("Failed to allocate bruteforce dictionary");
        return 0;
    }

    uint16_t idx = 0;

    // Start with variations
    nfc3d_keygen_masterkeys* temp_dict = NULL;
    uint16_t variations_count = dict_generator_variations(&temp_dict);
    
    // Copy variations to output
    uint16_t to_copy = (variations_count < max_entries) ? variations_count : max_entries;
    memcpy(*out_dict, temp_dict, to_copy * sizeof(nfc3d_keygen_masterkeys));
    free(temp_dict);
    idx = to_copy;

    // Add single-byte modified patterns
    if (idx < max_entries) {
        for (int byte_val = 0; byte_val < 256 && idx < max_entries; byte_val += 16) {
            memset(&(*out_dict)[idx], byte_val, sizeof(nfc3d_keygen_masterkeys));
            (*out_dict)[idx].magicBytesSize = 1;
            idx++;
        }
    }

    NRF_LOG_INFO("Generated %d bruteforce lite dictionary entries", idx);
    return idx;
}

bool dict_generator_is_cached(void)
{
    return g_dictionary != NULL && g_dictionary_size > 0;
}

const nfc3d_keygen_masterkeys* dict_generator_get_cached(uint16_t* out_size)
{
    if (out_size != NULL) {
        *out_size = g_dictionary_size;
    }
    return g_dictionary;
}

void dict_generator_clear_cache(void)
{
    if (g_dictionary != NULL) {
        free(g_dictionary);
        g_dictionary = NULL;
        g_dictionary_size = 0;
    }
    NRF_LOG_INFO("Dictionary cache cleared");
}

void dict_generator_deinit(void)
{
    dict_generator_clear_cache();
    NRF_LOG_INFO("Dictionary generator deinitialized");
}
