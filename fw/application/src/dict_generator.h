/*
 * NFC Dictionary Generator Header
 * Runtime generation of master key candidates
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef DICT_GENERATOR_H
#define DICT_GENERATOR_H

#include <stdint.h>
#include <stdbool.h>
#include "nfc3d/keygen.h"

/**
 * Dictionary generation modes
 */
typedef enum
{
    DICT_GEN_MODE_BASIC = 0,        // Basic known patterns only
    DICT_GEN_MODE_VARIATIONS = 1,   // Basic + byte variations
    DICT_GEN_MODE_BRUTEFORCE = 2,   // Extended brute force
} dict_generator_mode_t;

/**
 * Dictionary size definitions
 */
#define BASIC_DICT_SIZE 10
#define VARIATIONS_DICT_EXTRA 50
#define BRUTEFORCE_DICT_SIZE 256

/**
 * Initialize dictionary generator
 */
void dict_generator_init(void);

/**
 * Generate dictionary in specified mode
 * Returns: number of keys generated
 * Allocates memory for dictionary - caller must free
 */
uint16_t dict_generator_generate(
    dict_generator_mode_t mode,
    nfc3d_keygen_masterkeys** out_dict
);

/**
 * Generate basic dictionary (known patterns)
 */
uint16_t dict_generator_basic(nfc3d_keygen_masterkeys** out_dict);

/**
 * Generate variations (basic + rotated/modified patterns)
 */
uint16_t dict_generator_variations(nfc3d_keygen_masterkeys** out_dict);

/**
 * Generate bruteforce candidate keys (limited set)
 */
uint16_t dict_generator_bruteforce_lite(nfc3d_keygen_masterkeys** out_dict);

/**
 * Check if dictionary is cached in memory
 */
bool dict_generator_is_cached(void);

/**
 * Get cached dictionary (do not free)
 */
const nfc3d_keygen_masterkeys* dict_generator_get_cached(uint16_t* out_size);

/**
 * Clear cached dictionary
 */
void dict_generator_clear_cache(void);

/**
 * Deinitialize and cleanup
 */
void dict_generator_deinit(void);

#endif // DICT_GENERATOR_H
