/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * coap_oscore.h -- Object Security for Constrained RESTful Environments
 *                  (OSCORE) support for libcoap
 *
 * Copyright (C) 2019-2023 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_tongsuomini.h
 * @brief CoAP with tongsuo mini
 */

#ifndef COAP_TONGSUOMINI_H_
#define COAP_TONGSUOMINI_H_

/**
 * @ingroup application_api
 * @defgroup oscore OSCORE Support
 * API functions for interfacing with OSCORE (RFC8613)
 * @{
 */
#include "coap3/coap_internal.h"
#include <tongsuo/oscore_context.h>

void oscore_free_contexts(coap_context_t *c_context);
void oscore_delete_server_associations(coap_session_t *session);
void cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr,
                                  TSM_STR *partial_iv);
void cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, TSM_STR *key_id);
oscore_ctx_t *
oscore_find_context(const coap_context_t *c_context,
                    const TSM_STR *rcpkey_id,
                    const TSM_STR *ctxkey_id,
                    uint8_t *oscore_r2,
                    oscore_recipient_ctx_t **recipient_ctx);
int
oscore_new_association(coap_session_t *session,
                       coap_pdu_t *sent_pdu,
                       coap_bin_const_t *token,
                       oscore_recipient_ctx_t *recipient_ctx,
                       TSM_STR *aad,
                       TSM_STR *nonce,
                       TSM_STR *partial_iv,
                       int is_observe);
oscore_association_t *
oscore_find_association(coap_session_t *session, coap_bin_const_t *token);
int
oscore_delete_association(coap_session_t *session,
                          oscore_association_t *association);
oscore_ctx_t *
oscore_derive_ctx(coap_context_t *c_context, coap_oscore_conf_t *oscore_conf);
int
oscore_remove_context(coap_context_t *c_context, oscore_ctx_t *osc_ctx);
void
oscore_update_ctx(oscore_ctx_t *osc_ctx, coap_bin_const_t *id_context);
oscore_ctx_t *
oscore_duplicate_ctx(coap_context_t *c_context,
                     oscore_ctx_t *o_osc_ctx,
                     TSM_STR *sender_id,
                     TSM_STR *recipient_id,
                     TSM_STR *id_context);
void
oscore_free_association(oscore_association_t *association);
oscore_recipient_ctx_t *
oscore_add_recipient(oscore_ctx_t *osc_ctx, coap_bin_const_t *rid,
                     uint32_t break_key);
int
oscore_delete_recipient(oscore_ctx_t *osc_ctx, coap_bin_const_t *rid);
void
cose_encrypt0_set_external_aad(cose_encrypt0_t *ptr,
                               coap_bin_const_t *external_aad);
void
cose_encrypt0_set_aad(cose_encrypt0_t *ptr, TSM_STR *aad);
int
cose_encrypt0_set_key(cose_encrypt0_t *ptr, TSM_STR *key);
void
cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr,
                              TSM_STR *kid_context);
void
cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, TSM_STR *nonce);

size_t oscore_cbor_put_nil(uint8_t **buffer, size_t *buf_size);

size_t oscore_cbor_put_true(uint8_t **buffer, size_t *buf_size);

size_t oscore_cbor_put_false(uint8_t **buffer, size_t *buf_size);

size_t oscore_cbor_put_text(uint8_t **buffer, size_t *buf_size, const char *text, size_t text_len);

size_t oscore_cbor_put_array(uint8_t **buffer, size_t *buf_size, size_t elements);

size_t oscore_cbor_put_bytes(uint8_t **buffer, size_t *buf_size, const uint8_t *bytes,
                             size_t bytes_len);

size_t oscore_cbor_put_map(uint8_t **buffer, size_t *buf_size, size_t elements);

size_t oscore_cbor_put_number(uint8_t **buffer, size_t *buf_size, int64_t value);

size_t oscore_cbor_put_simple_value(uint8_t **buffer, size_t *buf_size, uint8_t value);

size_t oscore_cbor_put_unsigned(uint8_t **buffer, size_t *buf_size, uint64_t value);

size_t oscore_cbor_put_tag(uint8_t **buffer, size_t *buf_size, uint64_t value);

size_t oscore_cbor_put_negative(uint8_t **buffer, size_t *buf_size, int64_t value);

uint8_t oscore_cbor_get_next_element(const uint8_t **buffer, size_t *buf_size);

size_t oscore_cbor_get_element_size(const uint8_t **buffer, size_t *buf_size);

uint8_t oscore_cbor_elem_contained(const uint8_t *data, size_t *buf_size, uint8_t *end);

uint8_t oscore_cbor_get_number(const uint8_t **data, size_t *buf_size, int64_t *value);

uint8_t oscore_cbor_get_simple_value(const uint8_t **data, size_t *buf_size, uint8_t *value);

int64_t oscore_cbor_get_negative_integer(const uint8_t **buffer, size_t *buf_size);

uint64_t oscore_cbor_get_unsigned_integer(const uint8_t **buffer, size_t *buf_size);

void oscore_cbor_get_string(const uint8_t **buffer, size_t *buf_size, char *str, size_t size);

void oscore_cbor_get_array(const uint8_t **buffer, size_t *buf_size, uint8_t *arr, size_t size);

/* oscore_cbor_get_string_array
 * fills the the size and the array from the cbor element
 */
uint8_t oscore_cbor_get_string_array(const uint8_t **data, size_t *buf_size, uint8_t **result,
                                     size_t *len);

/* oscore_cbor_strip value
 * strips the value of the cbor element into result
 *  and returns size
 */
uint8_t oscore_cbor_strip_value(const uint8_t **data, size_t *buf_size, uint8_t **result,
                                size_t *len);

void oscore_log_hex_value(int level, const char *name, TSM_STR *value);

void oscore_log_char_value(int level, const char *name, const char *value);

void cose_encrypt0_init(cose_encrypt0_t *ptr);

void cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg);

void cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);

void cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);

/* Return length */
size_t cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, const uint8_t **buffer);

/* Return length */
size_t cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, const uint8_t **buffer);

int cose_encrypt0_encrypt(cose_encrypt0_t *ptr, uint8_t *ciphertext_buffer, size_t ciphertext_len);

int cose_encrypt0_decrypt(cose_encrypt0_t *ptr, uint8_t *plaintext_buffer, size_t plaintext_len);

size_t oscore_encode_option_value(uint8_t *option_buffer,
                                  size_t option_buf_len,
                                  cose_encrypt0_t *cose,
                                  uint8_t group,
                                  uint8_t appendix_b_2);

/*
 * Decodes the OSCORE option value and places decoded values into the provided
 * cose structure */
int oscore_decode_option_value(const uint8_t *option_value,
                               size_t option_len,
                               cose_encrypt0_t *cose);

/* Creates AAD, creates External AAD and serializes it into the complete AAD
 * structure. Returns serialized size. */
size_t oscore_prepare_aad(const uint8_t *external_aad_buffer,
                          size_t external_aad_len,
                          uint8_t *aad_buffer,
                          size_t aad_size);

size_t oscore_prepare_e_aad(oscore_ctx_t *ctx,
                            cose_encrypt0_t *cose,
                            const uint8_t *oscore_option,
                            size_t oscore_option_len,
                            TSM_STR *sender_public_key,
                            uint8_t *external_aad_ptr,
                            size_t external_aad_size);

/* Creates Nonce */
void oscore_generate_nonce(cose_encrypt0_t *ptr, oscore_ctx_t *ctx, uint8_t *buffer, uint8_t size);

/*Return 1 if OK, Error code otherwise */
uint8_t oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose);

/* Return 0 if SEQ MAX, return 1 if OK */
uint8_t oscore_increment_sender_seq(oscore_ctx_t *ctx);

/* Restore the sequence number and replay-window to the previous state. This is
 * to be used when decryption fail. */
void oscore_roll_back_seq(oscore_recipient_ctx_t *ctx);

const char *cose_get_alg_name(cose_alg_t id, char *buffer, size_t buflen);

size_t cose_tag_len(cose_alg_t cose_alg);
#endif /* COAP_TONGSUOMINI_H_ */
