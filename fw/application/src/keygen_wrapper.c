/*
 * NFC Keygen Wrapper Implementation
 * Wraps the standard keygen function to support dictionary-based key cracking
 *
 * SPDX-License-Identifier: MIT
 */

#include "keygen_wrapper.h"
#include "dict_attack.h"
#include "dict_generator.h"
#include "nfc3d/keygen.h"
#include "nrf_log.h"
#include <string.h>

static keygen_mode_t g_keygen_mode = KEYGEN_MODE_NORMAL;
static bool g_dict_attack_enabled = true;

void keygen_wrapper_init(void)
{
    dict_attack_init();
    NRF_LOG_INFO("Keygen wrapper initialized");
}.

void keygen_wrapper_set_mode(keygen_mode_t mode)
{
    g_keygen_mode = mode;
    NRF_LOG_INFO("Keygen mode set to: %d", mode);
}

keygen_mode_t keygen_wrapper_get_mode(void)
{
    return g_keygen_mode;
}

void keygen_wrapper_keygen(
    const nfc3d_keygen_masterkeys* baseKeys,
    const uint8_t* baseSeed,
    nfc3d_keygen_derivedkeys* derivedKeys
)
{
    if (baseKeys == NULL || baseSeed == NULL || derivedKeys == NULL) {
        NRF_LOG_ERROR("Invalid parameters to keygen_wrapper_keygen");
        return;
    }

    if (g_dict_attack_enabled && g_keygen_mode == KEYGEN_MODE_DICT_ATTACK) {
        NRF_LOG_INFO("Attempting dictionary attack on key generation");
        
        nfc3d_keygen_masterkeys found_keys = {0};
        nfc3d_keygen_derivedkeys found_derived = {0};
        
        bool success = dict_attack_crack_key(baseSeed, &found_keys, &found_derived);
        
        if (success) {
            memcpy((void*)derivedKeys, &found_derived, sizeof(nfc3d_keygen_derivedkeys));
            NRF_LOG_INFO("Dictionary attack successful!");
            return;
        } else {
            NRF_LOG_WARNING("Dictionary attack failed, falling back to normal keygen");
        }
    }

    // Fall through to normal key generation
    nfc3d_keygen(baseKeys, baseSeed, derivedKeys);
}

void keygen_wrapper_set_dict_attack_enabled(bool enabled)
{
    g_dict_attack_enabled = enabled;
    dict_attack_set_enabled(enabled);
    NRF_LOG_INFO("Dictionary attack %s", enabled ? "enabled" : "disabled");
}

bool keygen_wrapper_is_dict_attack_enabled(void)
{
    return g_dict_attack_enabled;
}
