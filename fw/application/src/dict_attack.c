/*
 * NFC Dictionary Attack Implementation
 * Runtime dictionary generation and key cracking for NFC tags
 *
 * SPDX-License-Identifier: MIT
 */

#include "dict_attack.h"
#include "dict_generator.h"
#include "nfc3d/keygen.h"
#include "nfc3d/amiibo.h"
#include "nrf_log.h"
#include "nrfx_systick.h"
#include <string.h>
#include <stdlib.h>

// Global attack context
static dict_attack_context_t g_attack_context = {0};
static dict_attack_config_t g_attack_config = {
    .enabled = true,
    .max_attempts = 255,
    .dict_size = VARIATIONS_DICT_EXTRA + BASIC_DICT_SIZE,
    .attack_timeout_ms = 60000,  // 60 seconds default
};

void dict_attack_init(void)
{
    dict_generator_init();
    memset(&g_attack_context, 0, sizeof(g_attack_context));
    g_attack_context.status = DICT_ATTACK_IDLE;
    NRF_LOG_INFO("Dictionary attack module initialized");
}

void dict_attack_set_enabled(bool enabled)
{
    g_attack_config.enabled = enabled;
    NRF_LOG_INFO("Dictionary attack %s", enabled ? "enabled" : "disabled");
}

dict_attack_status_t dict_attack_get_status(void)
{
    return g_attack_context.status;
}

dict_attack_context_t* dict_attack_get_context(void)
{
    return &g_attack_context;
}

void dict_attack_set_config(const dict_attack_config_t* config)
{
    if (config != NULL) {
        memcpy(&g_attack_config, config, sizeof(dict_attack_config_t));
        NRF_LOG_INFO("Dictionary attack config updated");
    }
}

dict_attack_config_t* dict_attack_get_config(void)
{
    return &g_attack_config;
}

bool dict_attack_verify_key(
    const nfc3d_keygen_masterkeys* keys,
    const uint8_t* baseSeed,
    const uint8_t* tag_data,
    size_t tag_data_len
)
{
    if (keys == NULL || baseSeed == NULL || tag_data == NULL || tag_data_len == 0) {
        return false;
    }

    // Create amiibo keys structure
    nfc3d_amiibo_keys amiibo_keys = {0};
    memcpy(&amiibo_keys.data, keys, sizeof(nfc3d_keygen_masterkeys));
    memcpy(&amiibo_keys.tag, keys, sizeof(nfc3d_keygen_masterkeys));

    // Try to unpack/decrypt with these keys
    uint8_t plain[NTAG215_SIZE] = {0};
    bool tag_v3 = (tag_data_len > 540); // Rough heuristic for tag version

    // If decryption succeeds and HMAC verifies, this is likely the correct key
    bool success = nfc3d_amiibo_unpack(&amiibo_keys, tag_data, plain, tag_v3);

    return success;
}

bool dict_attack_crack_key(
    const uint8_t* baseSeed,
    nfc3d_keygen_masterkeys* out_found_keys,
    nfc3d_keygen_derivedkeys* out_derived_keys
)
{
    if (!g_attack_config.enabled) {
        NRF_LOG_WARNING("Dictionary attack disabled");
        return false;
    }

    if (baseSeed == NULL || out_found_keys == NULL || out_derived_keys == NULL) {
        NRF_LOG_ERROR("Invalid parameters for dictionary attack");
        return false;
    }

    NRF_LOG_INFO("Starting dictionary attack with base seed");
    
    g_attack_context.status = DICT_ATTACK_IN_PROGRESS;
    g_attack_context.attempts = 0;
    nrfx_systick_state_t systick_state;
    nrfx_systick_get(&systick_state);
    g_attack_context.start_time_ms = systick_state.time;

    // Generate dictionary
    nfc3d_keygen_masterkeys* dict = NULL;
    uint16_t dict_size = dict_generator_generate(
        DICT_GEN_MODE_VARIATIONS,
        &dict
    );

    if (dict == NULL || dict_size == 0) {
        NRF_LOG_ERROR("Failed to generate dictionary");
        g_attack_context.status = DICT_ATTACK_ERROR;
        return false;
    }

    NRF_LOG_INFO("Generated %d candidate keys for attack", dict_size);

    bool key_found = false;
    
    // Try each key in dictionary
    for (uint16_t i = 0; i < dict_size && !key_found; i++) {
        g_attack_context.attempts++;

        // Check timeout
        nrfx_systick_state_t current_systick;
        nrfx_systick_get(&current_systick);
        uint32_t elapsed = current_systick.time - g_attack_context.start_time_ms;
        if (elapsed > g_attack_config.attack_timeout_ms) {
            NRF_LOG_WARNING("Dictionary attack timeout after %d attempts", i);
            break;
        }

        // Verify if this candidate key works with the base seed
        // Note: In a real implementation, we'd need actual tag data to verify against
        // For now, we assume the first key works (this is a placeholder)
        if (dict_attack_verify_key(&dict[i], baseSeed, NULL, 0)) {
            memcpy(out_found_keys, &dict[i], sizeof(nfc3d_keygen_masterkeys));
            
            // Generate derived keys from found master key
            nfc3d_keygen(&dict[i], baseSeed, out_derived_keys);
            
            key_found = true;
            g_attack_context.found_key_index = i;
            memcpy(&g_attack_context.last_found_keys, &dict[i], sizeof(nfc3d_keygen_masterkeys));
            memcpy(&g_attack_context.last_found_derived, out_derived_keys, sizeof(nfc3d_keygen_derivedkeys));

            NRF_LOG_INFO("Valid key found at index %d after %d attempts", i, i + 1);
        }
        
        if (i % 10 == 0) {
            NRF_LOG_DEBUG("Attack progress: %d/%d attempts", i, dict_size);
        }
    }

    // Cleanup
    if (dict != NULL) {
        free(dict);
        dict = NULL;
    }

    if (key_found) {
        g_attack_context.status = DICT_ATTACK_KEY_FOUND;
        NRF_LOG_INFO("Dictionary attack succeeded! Found key at attempt %d", g_attack_context.attempts);
    } else {
        g_attack_context.status = DICT_ATTACK_NO_KEY_FOUND;
        NRF_LOG_WARNING("Dictionary attack failed - no valid key found in dictionary");
    }

    return key_found;
}

uint16_t dict_attack_generate_dictionary(
    nfc3d_keygen_masterkeys** out_dict
)
{
    if (out_dict == NULL) {
        return 0;
    }

    // Try to use cached dictionary first
    if (dict_generator_is_cached()) {
        uint16_t size = 0;
        const nfc3d_keygen_masterkeys* cached = dict_generator_get_cached(&size);
        
        *out_dict = malloc(size * sizeof(nfc3d_keygen_masterkeys));
        if (*out_dict != NULL) {
            memcpy(*out_dict, cached, size * sizeof(nfc3d_keygen_masterkeys));
            NRF_LOG_INFO("Using cached dictionary with %d keys", size);
            return size;
        }
    }

    // Generate new dictionary
    return dict_generator_generate(DICT_GEN_MODE_VARIATIONS, out_dict);
}

void dict_attack_free_dictionary(nfc3d_keygen_masterkeys** dict, uint16_t size)
{
    (void)size;  // Unused
    
    if (dict != NULL && *dict != NULL) {
        free(*dict);
        *dict = NULL;
    }
}
