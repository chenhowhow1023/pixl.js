/*
 * NFC Dictionary Attack Module
 * Runtime dictionary generation and key cracking for NFC tags
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef DICT_ATTACK_H
#define DICT_ATTACK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "nfc3d/keygen.h"
#include "nfc3d/amiibo.h"

/**
 * Dictionary attack result status
 */
typedef enum
{
    DICT_ATTACK_IDLE = 0,
    DICT_ATTACK_IN_PROGRESS = 1,
    DICT_ATTACK_KEY_FOUND = 2,
    DICT_ATTACK_NO_KEY_FOUND = 3,
    DICT_ATTACK_ERROR = 4,
} dict_attack_status_t;

/**
 * Dictionary attack configuration
 */
typedef struct
{
    bool enabled;                              // Enable/disable dictionary attack
    uint8_t max_attempts;                      // Max attempts before giving up
    uint16_t dict_size;                        // Number of keys in dictionary
    uint32_t attack_timeout_ms;                // Timeout in milliseconds
} dict_attack_config_t;

/**
 * Dictionary attack context
 */
typedef struct
{
    dict_attack_status_t status;
    uint32_t attempts;
    uint8_t found_key_index;
    nfc3d_keygen_masterkeys last_found_keys;
    nfc3d_keygen_derivedkeys last_found_derived;
    uint32_t start_time_ms;
} dict_attack_context_t;

/**
 * Initialize dictionary attack module
 */
void dict_attack_init(void);

/**
 * Enable/disable dictionary attack
 */
void dict_attack_set_enabled(bool enabled);

/**
 * Get current status
 */
dict_attack_status_t dict_attack_get_status(void);

/**
 * Get attack context
 */
dict_attack_context_t* dict_attack_get_context(void);

/**
 * Try to crack a key using dictionary
 * Returns: true if key was found, false otherwise
 */
bool dict_attack_crack_key(
    const uint8_t* baseSeed,
    nfc3d_keygen_masterkeys* out_found_keys,
    nfc3d_keygen_derivedkeys* out_derived_keys
);

/**
 * Generate dictionary at runtime
 * Generates common master key variations
 * Returns: number of keys generated
 */
uint16_t dict_attack_generate_dictionary(
    nfc3d_keygen_masterkeys** out_dict
);

/**
 * Free generated dictionary
 */
void dict_attack_free_dictionary(nfc3d_keygen_masterkeys** dict, uint16_t size);

/**
 * Set custom configuration
 */
void dict_attack_set_config(const dict_attack_config_t* config);

/**
 * Get current configuration
 */
dict_attack_config_t* dict_attack_get_config(void);

/**
 * Verify if a key is valid by attempting decryption
 */
bool dict_attack_verify_key(
    const nfc3d_keygen_masterkeys* keys,
    const uint8_t* baseSeed,
    const uint8_t* tag_data,
    size_t tag_data_len
);

#endif // DICT_ATTACK_H
