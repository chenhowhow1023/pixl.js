/*
 * NFC Keygen Wrapper with Dictionary Attack Support
 * Wraps the standard keygen function to support dictionary-based key cracking
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KEYGEN_WRAPPER_H
#define KEYGEN_WRAPPER_H

#include "nfc3d/keygen.h"
#include <stdbool.h>

/**
 * Mode for keygen operation
 */
typedef enum
{
    KEYGEN_MODE_NORMAL = 0,      // Normal key generation
    KEYGEN_MODE_DICT_ATTACK = 1, // Dictionary attack mode
} keygen_mode_t;

/**
 * Initialize keygen wrapper
 */
void keygen_wrapper_init(void);

/**
 * Set keygen operation mode
 */
void keygen_wrapper_set_mode(keygen_mode_t mode);

/**
 * Get current keygen mode
 */
keygen_mode_t keygen_wrapper_get_mode(void);

/**
 * Wrapper for nfc3d_keygen with optional dictionary attack
 * If mode is KEYGEN_MODE_DICT_ATTACK, attempts to crack the key
 * Otherwise behaves like normal nfc3d_keygen
 */
void keygen_wrapper_keygen(
    const nfc3d_keygen_masterkeys* baseKeys,
    const uint8_t* baseSeed,
    nfc3d_keygen_derivedkeys* derivedKeys
);

/**
 * Enable/disable dictionary attack globally
 */
void keygen_wrapper_set_dict_attack_enabled(bool enabled);

/**
 * Check if dictionary attack is enabled
 */
bool keygen_wrapper_is_dict_attack_enabled(void);

#endif // KEYGEN_WRAPPER_H
