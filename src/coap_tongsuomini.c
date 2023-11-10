/*
 * coap_notls.c -- Stub Datagram Transport Layer Support for libcoap
 *
 * Copyright (C) 2016      Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_tongsuomini.c
 * @brief Tongsuo Mini specific interface functions
 */

#include "coap3/coap_internal.h"

#ifdef COAP_WITH_LIBTONGSUOMINI

int
coap_dtls_is_supported(void) {
  return 0;
}

int
coap_tls_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_psk_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_pki_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_pkcs11_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_rpk_is_supported(void) {
  return 0;
}

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  version.version = TONGSUO_MINI_VERSION;
  version.built_version = TONGSUO_MINI_VERSION;
  version.type = COAP_TLS_LIBRARY_TONGSUOMINI;
  return &version;
}

int
coap_dtls_context_set_pki(coap_context_t *ctx COAP_UNUSED,
                          const coap_dtls_pki_t *setup_data COAP_UNUSED,
                          const coap_dtls_role_t role COAP_UNUSED
                         ) {
  return 0;
}

int
coap_dtls_context_set_pki_root_cas(coap_context_t *ctx COAP_UNUSED,
                                   const char *ca_file COAP_UNUSED,
                                   const char *ca_path COAP_UNUSED
                                  ) {
  return 0;
}

#if COAP_CLIENT_SUPPORT
int
coap_dtls_context_set_cpsk(coap_context_t *ctx COAP_UNUSED,
                           coap_dtls_cpsk_t *setup_data COAP_UNUSED
                          ) {
  return 0;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
int
coap_dtls_context_set_spsk(coap_context_t *ctx COAP_UNUSED,
                           coap_dtls_spsk_t *setup_data COAP_UNUSED
                          ) {
  return 0;
}
#endif /* COAP_SERVER_SUPPORT */

int
coap_dtls_context_check_keys_enabled(coap_context_t *ctx COAP_UNUSED) {
  return 0;
}

static coap_log_t dtls_log_level = COAP_LOG_EMERG;

void
coap_dtls_startup(void) {
}

void *
coap_dtls_get_tls(const coap_session_t *c_session COAP_UNUSED,
                  coap_tls_library_t *tls_lib) {
  if (tls_lib)
    *tls_lib = COAP_TLS_LIBRARY_NOTLS;
  return NULL;
}

void
coap_dtls_shutdown(void) {
  coap_dtls_set_log_level(COAP_LOG_EMERG);
}

void
coap_dtls_set_log_level(coap_log_t level) {
  dtls_log_level = level;
}

coap_log_t
coap_dtls_get_log_level(void) {
  return dtls_log_level;
}

void *
coap_dtls_new_context(coap_context_t *coap_context COAP_UNUSED) {
  return NULL;
}

void
coap_dtls_free_context(void *handle COAP_UNUSED) {
}

#if COAP_SERVER_SUPPORT
void *
coap_dtls_new_server_session(coap_session_t *session COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
void *
coap_dtls_new_client_session(coap_session_t *session COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_CLIENT_SUPPORT */

void
coap_dtls_free_session(coap_session_t *coap_session COAP_UNUSED) {
}

void
coap_dtls_session_update_mtu(coap_session_t *session COAP_UNUSED) {
}

ssize_t
coap_dtls_send(coap_session_t *session COAP_UNUSED,
               const uint8_t *data COAP_UNUSED,
               size_t data_len COAP_UNUSED) {
  return -1;
}

int
coap_dtls_is_context_timeout(void) {
  return 1;
}

coap_tick_t
coap_dtls_get_context_timeout(void *dtls_context COAP_UNUSED) {
  return 0;
}

coap_tick_t
coap_dtls_get_timeout(coap_session_t *session COAP_UNUSED, coap_tick_t now COAP_UNUSED) {
  return 0;
}

/*
 * return 1 timed out
 *        0 still timing out
 */
int
coap_dtls_handle_timeout(coap_session_t *session COAP_UNUSED) {
  return 0;
}

int
coap_dtls_receive(coap_session_t *session COAP_UNUSED,
                  const uint8_t *data COAP_UNUSED,
                  size_t data_len COAP_UNUSED
                 ) {
  return -1;
}

#if COAP_SERVER_SUPPORT
int
coap_dtls_hello(coap_session_t *session COAP_UNUSED,
                const uint8_t *data COAP_UNUSED,
                size_t data_len COAP_UNUSED
               ) {
  return 0;
}
#endif /* COAP_SERVER_SUPPORT */

unsigned int
coap_dtls_get_overhead(coap_session_t *session COAP_UNUSED) {
  return 0;
}

#if COAP_CLIENT_SUPPORT
void *
coap_tls_new_client_session(coap_session_t *session COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
void *
coap_tls_new_server_session(coap_session_t *session COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

void
coap_tls_free_session(coap_session_t *coap_session COAP_UNUSED) {
}

/*
 * strm
 * return +ve Number of bytes written.
 *         -1 Error (error in errno).
 */
ssize_t
coap_tls_write(coap_session_t *session COAP_UNUSED,
               const uint8_t *data COAP_UNUSED,
               size_t data_len COAP_UNUSED) {
  return -1;
}

/*
 * strm
 * return >=0 Number of bytes read.
 *         -1 Error (error in errno).
 */
ssize_t
coap_tls_read(coap_session_t *session COAP_UNUSED,
              uint8_t *data COAP_UNUSED,
              size_t data_len COAP_UNUSED) {
  return -1;
}

#if COAP_SERVER_SUPPORT
typedef struct coap_local_hash_t {
  size_t ofs;
  coap_key_t key[8];   /* 32 bytes in total */
} coap_local_hash_t;

coap_digest_ctx_t *
coap_digest_setup(void) {
  coap_key_t *digest_ctx = coap_malloc_type(COAP_DIGEST_CTX, sizeof(coap_local_hash_t));

  if (digest_ctx) {
    memset(digest_ctx, 0, sizeof(coap_local_hash_t));
  }

  return digest_ctx;
}

void
coap_digest_free(coap_digest_ctx_t *digest_ctx) {
  coap_free_type(COAP_DIGEST_CTX, digest_ctx);
}

int
coap_digest_update(coap_digest_ctx_t *digest_ctx,
                   const uint8_t *data,
                   size_t data_len) {
  coap_local_hash_t *local = (coap_local_hash_t *)digest_ctx;

  coap_hash(data, data_len, local->key[local->ofs]);

  local->ofs = (local->ofs + 1) % 7;
  return 1;
}

int
coap_digest_final(coap_digest_ctx_t *digest_ctx,
                  coap_digest_t *digest_buffer) {
  coap_local_hash_t *local = (coap_local_hash_t *)digest_ctx;

  memcpy(digest_buffer, local->key, sizeof(coap_digest_t));

  coap_digest_free(digest_ctx);
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_WS_SUPPORT
int
coap_crypto_hash(cose_alg_t alg,
                 const coap_bin_const_t *data,
                 coap_bin_const_t **hash) {
  (void)alg;
  (void)data;
  (void)hash;
  return 0;
}
#endif /* COAP_WS_SUPPORT */

#if COAP_OSCORE_SUPPORT

int
coap_oscore_is_supported(void) {
  return 1;
}

int
coap_crypto_check_cipher_alg(cose_alg_t alg) {
  if (alg == COSE_ALGORITHM_ASCON_AEAD_16_128_128
     || alg == COSE_ALGORITHM_ASCON_AEAD_64_128_128)
    return 1;
  
  return 0;
}

int
coap_crypto_check_hkdf_alg(cose_hkdf_alg_t hkdf_alg) {
  cose_hmac_alg_t hmac_alg;

  if (tsm_cose_get_hmac_alg_for_hkdf(hkdf_alg, &hmac_alg) != TSM_OK)
    return 0;

  return 1;
}

int
coap_crypto_aead_encrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  (void)params;
  (void)data;
  (void)aad;
  (void)result;
  *max_result_len = 0;
  return 0;
}

int
coap_crypto_aead_decrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  (void)params;
  (void)data;
  (void)aad;
  (void)result;
  *max_result_len = 0;
  return 0;
}

int
coap_crypto_hmac(cose_hmac_alg_t hmac_alg,
                 coap_bin_const_t *key,
                 coap_bin_const_t *data,
                 coap_bin_const_t **hmac) {
  (void)hmac_alg;
  (void)key;
  (void)data;
  (void)hmac;
  return 0;
}

void
oscore_free_contexts(coap_context_t *c_context)
{
    while (c_context->p_osc_ctx) {
        oscore_ctx_t *osc_ctx = c_context->p_osc_ctx;

        c_context->p_osc_ctx = osc_ctx->next;

        tsm_oscore_ctx_free(osc_ctx);
    }
}

int
oscore_new_association(coap_session_t *session,
                       coap_pdu_t *sent_pdu,
                       coap_bin_const_t *token,
                       oscore_recipient_ctx_t *recipient_ctx,
                       TSM_STR *aad,
                       TSM_STR *nonce,
                       TSM_STR *partial_iv,
                       int is_observe) {
  oscore_association_t *association;

  TSM_STR token_str = {token->length, token->s};
  association = tsm_oscore_association_new(&token_str, recipient_ctx, aad, nonce, partial_iv, is_observe);

  if (sent_pdu) {
    size_t size;
    const uint8_t *data;

    association->sent_pdu =
      coap_pdu_duplicate(sent_pdu, session, token->length, token->s, NULL);
    if (association->sent_pdu == NULL)
      goto error;
    if (coap_get_data(sent_pdu, &size, &data)) {
      coap_add_data(association->sent_pdu, size, data);
    }
  }

  // FIXME
  if (session->associations == NULL)
    session->associations = association;
  else
    session->associations->next = association;

  return 1;

error:
  tsm_oscore_association_free(association);
  return 0;
}

oscore_association_t *
oscore_find_association(coap_session_t *session, coap_bin_const_t *token) {
  TSM_STR token_str = {token->length, token->s};
  return tsm_oscore_association_find(session->associations, &token_str);
}

/*
 * oscore_find_context
 * Finds OSCORE context for rcpkey_id and optional ctxkey_id
 * rcpkey_id can be 0 length.
 * Updates recipient_ctx.
 */
oscore_ctx_t *
oscore_find_context(const coap_context_t *c_context,
                    const TSM_STR *rcpkey_id,
                    const TSM_STR *ctxkey_id,
                    uint8_t *oscore_r2,
                    oscore_recipient_ctx_t **recipient_ctx) {
  oscore_ctx_t *pt = c_context->p_osc_ctx;

  *recipient_ctx = NULL;
  assert(rcpkey_id->length == 0 || rcpkey_id->s != NULL);
  while (pt != NULL) {
    oscore_recipient_ctx_t *rcpctx = tsm_oscore_find_recipient(pt, rcpkey_id, ctxkey_id, oscore_r2);

    if (rcpctx) {
      *recipient_ctx = rcpctx;
      return pt;
    }

    pt = pt->next;
  } /* end while */
  return NULL;
}

void
oscore_delete_server_associations(coap_session_t *session) {
  if (session) {
    tsm_oscore_association_free_all(session->associations, oscore_free_association);
    session->associations = NULL;
  }
}

void
cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr,
                             TSM_STR *partial_iv) {
  if (partial_iv == NULL)
      tsm_cose_encrypt0_set_partial_iv(ptr, NULL, 0);
  else
    tsm_cose_encrypt0_set_partial_iv(ptr, partial_iv->s, partial_iv->length);
}

void
cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, TSM_STR *key_id) {
  if (key_id == NULL)
    tsm_cose_encrypt0_set_key_id(ptr, NULL, 0);
  else
    tsm_cose_encrypt0_set_key_id(ptr, key_id->s, key_id->length);
}

void
cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, TSM_STR *nonce) {
  if (nonce == NULL)
    tsm_cose_encrypt0_set_nonce(ptr, NULL, 0);
  else
    tsm_cose_encrypt0_set_nonce(ptr, nonce->s, nonce->length);
}

void
cose_encrypt0_set_external_aad(cose_encrypt0_t *ptr,
                               coap_bin_const_t *external_aad) {
  if (external_aad == NULL)
    tsm_cose_encrypt0_set_external_aad(ptr, NULL, 0);
  else
    tsm_cose_encrypt0_set_external_aad(ptr, external_aad->s, external_aad->length);
}

void
cose_encrypt0_set_aad(cose_encrypt0_t *ptr, TSM_STR *aad) {
  if (aad == NULL)
    tsm_cose_encrypt0_set_aad(ptr, NULL, 0);
  else
    tsm_cose_encrypt0_set_aad(ptr, aad->s, aad->length);
}

int
cose_encrypt0_set_key(cose_encrypt0_t *ptr, TSM_STR *key) {
  if (key == NULL)
    return tsm_cose_encrypt0_set_key(ptr, NULL, 0) == TSM_OK;
  else
    return tsm_cose_encrypt0_set_key(ptr, key->s, key->length) == TSM_OK;
}

void
cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr,
                              TSM_STR *kid_context) {
  if (kid_context == NULL)
    tsm_cose_encrypt0_set_kid_context(ptr, NULL, 0);
  else
    tsm_cose_encrypt0_set_kid_context(ptr, kid_context->s, kid_context->length);
}

int
oscore_delete_association(coap_session_t *session,
                          oscore_association_t *association) {
  if (association) {
    tsm_oscore_association_delete(&session->associations, association);
    oscore_free_association(association);
    return 1;
  }
  return 0;
}

void
oscore_free_association(oscore_association_t *association) {
  if (association) {
    coap_delete_pdu(association->sent_pdu);
    association->sent_pdu = NULL;
    tsm_oscore_association_free(association);
  }
}

int
oscore_delete_recipient(oscore_ctx_t *osc_ctx, coap_bin_const_t *rid) {
  TSM_STR rid_str = {rid->length, rid->s};
  return tsm_oscore_delete_recipient(osc_ctx, &rid_str) == TSM_OK;
}

oscore_recipient_ctx_t *
oscore_add_recipient(oscore_ctx_t *osc_ctx, coap_bin_const_t *rid,
                     uint32_t break_key) {
  TSM_STR rid_str = {rid->length, rid->s};
  return tsm_oscore_add_recipient(osc_ctx, &rid_str, break_key);
}

static int
coap_oscore_conf_to_tsm_oscore_conf(coap_oscore_conf_t *oscore_conf, TSM_OSCORE_CONF *oscf)
{
    if (oscore_conf->master_secret) {
        oscf->master_secret = tsm_str_new(oscore_conf->master_secret->s, oscore_conf->master_secret->length);
        if (oscf->master_secret == NULL)
            return TSM_ERR_MALLOC_FAILED;
    }

    if (oscore_conf->master_salt) {
        oscf->master_salt = tsm_str_new(oscore_conf->master_salt->s, oscore_conf->master_salt->length);
        if (oscf->master_salt == NULL)
            return TSM_ERR_MALLOC_FAILED;
    }
    if (oscore_conf->sender_id) {
        oscf->sender_id = tsm_str_new(oscore_conf->sender_id->s, oscore_conf->sender_id->length);
        if (oscf->sender_id == NULL)
            return TSM_ERR_MALLOC_FAILED;
    }

    if (oscore_conf->id_context) {
        oscf->id_context = tsm_str_new(oscore_conf->id_context->s, oscore_conf->id_context->length);
        if (oscf->id_context == NULL)
            return TSM_ERR_MALLOC_FAILED;
    }

    oscf->recipient_id_count = oscore_conf->recipient_id_count;

    oscf->recipient_id = tsm_alloc(sizeof(TSM_STR) * oscf->recipient_id_count + 1);
    if (oscf->recipient_id == NULL)
        return TSM_ERR_MALLOC_FAILED;

    for (uint32_t i = 0; i < oscf->recipient_id_count; i++) {
        oscf->recipient_id[i] = tsm_str_new(oscore_conf->recipient_id[i]->s, oscore_conf->recipient_id[i]->length);
        if (oscf->recipient_id[i] == NULL)
            return TSM_ERR_MALLOC_FAILED;
    }

    oscf->replay_window = oscore_conf->replay_window;
    oscf->ssn_freq = oscore_conf->ssn_freq;
    oscf->aead_alg = oscore_conf->aead_alg;
    oscf->hkdf_alg = oscore_conf->hkdf_alg;
    oscf->rfc8613_b_1_2 = oscore_conf->rfc8613_b_1_2;
    oscf->rfc8613_b_2 = oscore_conf->rfc8613_b_2;
    oscf->break_sender_key = oscore_conf->break_sender_key;
    oscf->break_recipient_key = oscore_conf->break_recipient_key;
    oscf->save_seq_num_func = oscore_conf->save_seq_num_func;
    oscf->save_seq_num_func_param = oscore_conf->save_seq_num_func_param;
    oscf->start_seq_num = oscore_conf->start_seq_num;

    return TSM_OK;
}

static void
oscore_enter_context(coap_context_t *c_context, oscore_ctx_t *osc_ctx) {
  if (c_context->p_osc_ctx) {
    oscore_ctx_t *prev = c_context->p_osc_ctx;
    oscore_ctx_t *next = c_context->p_osc_ctx->next;

    while (next) {
      prev = next;
      next = next->next;
    }
    prev->next = osc_ctx;
  } else
    c_context->p_osc_ctx = osc_ctx;
}

oscore_ctx_t *
oscore_duplicate_ctx(coap_context_t *c_context,
                     oscore_ctx_t *o_osc_ctx,
                     TSM_STR *sender_id,
                     TSM_STR *recipient_id,
                     TSM_STR *id_context)
{
  oscore_ctx_t *osc_ctx = NULL;

  osc_ctx = tsm_oscore_ctx_dup(o_osc_ctx, sender_id, recipient_id, id_context);
  if (osc_ctx == NULL)
    goto error;

  oscore_enter_context(c_context, osc_ctx);
  return osc_ctx;

error:
  tsm_oscore_ctx_free(osc_ctx);
  return NULL;
}

int oscore_remove_context(coap_context_t *c_context, oscore_ctx_t *osc_ctx)
{
  oscore_ctx_t *prev = NULL;
  oscore_ctx_t *next = c_context->p_osc_ctx;
  while (next) {
    if (next == osc_ctx) {
      if (prev != NULL)
        prev->next = next->next;
      else
        c_context->p_osc_ctx = next->next;

      tsm_oscore_ctx_free(next);
      return 1;
    }
    prev = next;
    next = next->next;
  }
  return 0;
}

oscore_ctx_t *
oscore_derive_ctx(coap_context_t *c_context, coap_oscore_conf_t *oscore_conf) {
  oscore_ctx_t *osc_ctx = NULL;
  TSM_OSCORE_CONF *oscf = NULL;

  oscf = tsm_oscore_conf_new();
  if (oscf == NULL)
    return NULL;

  if (coap_oscore_conf_to_tsm_oscore_conf(oscore_conf, oscf) != TSM_OK)
    goto err;

  osc_ctx = tsm_oscore_ctx_new(oscf);
  if (osc_ctx == NULL)
    goto err;

  oscore_enter_context(c_context, osc_ctx);

  tsm_oscore_conf_free(oscf);
  return osc_ctx;

err:
  tsm_oscore_conf_free(oscf);
  return NULL;
}

void
oscore_update_ctx(oscore_ctx_t *osc_ctx, coap_bin_const_t *id_context) {
  tsm_oscore_ctx_update(osc_ctx, tsm_str_new(id_context->s, id_context->length));
}

size_t oscore_cbor_put_nil(uint8_t **buffer, size_t *buf_size)
{
    return tsm_oscore_cbor_put_nil(buffer, buf_size);
}

size_t oscore_cbor_put_true(uint8_t **buffer, size_t *buf_size)
{
    return tsm_oscore_cbor_put_true(buffer, buf_size);
}

size_t oscore_cbor_put_false(uint8_t **buffer, size_t *buf_size)
{
    return tsm_oscore_cbor_put_false(buffer, buf_size);
}

size_t oscore_cbor_put_text(uint8_t **buffer, size_t *buf_size, const char *text, size_t text_len)
{
    return tsm_oscore_cbor_put_text(buffer, buf_size, text, text_len);
}

size_t oscore_cbor_put_array(uint8_t **buffer, size_t *buf_size, size_t elements)
{
    return tsm_oscore_cbor_put_array(buffer, buf_size, elements);
}

size_t oscore_cbor_put_bytes(uint8_t **buffer, size_t *buf_size, const uint8_t *bytes,
                             size_t bytes_len)
{
    return tsm_oscore_cbor_put_bytes(buffer, buf_size, bytes, bytes_len);
}

size_t oscore_cbor_put_map(uint8_t **buffer, size_t *buf_size, size_t elements)
{
    return tsm_oscore_cbor_put_map(buffer, buf_size, elements);
}

size_t oscore_cbor_put_number(uint8_t **buffer, size_t *buf_size, int64_t value)
{
    return tsm_oscore_cbor_put_number(buffer, buf_size, value);
}

size_t oscore_cbor_put_simple_value(uint8_t **buffer, size_t *buf_size, uint8_t value)
{
    return tsm_oscore_cbor_put_simple_value(buffer, buf_size, value);
}

size_t oscore_cbor_put_tag(uint8_t **buffer, size_t *buf_size, uint64_t value)
{
    return tsm_oscore_cbor_put_tag(buffer, buf_size, value);
}

size_t oscore_cbor_put_negative(uint8_t **buffer, size_t *buf_size, int64_t value)
{
    return tsm_oscore_cbor_put_negative(buffer, buf_size, value);
}

size_t oscore_cbor_put_unsigned(uint8_t **buffer, size_t *buf_size, uint64_t value)
{
    return tsm_oscore_cbor_put_unsigned(buffer, buf_size, value);
}


uint8_t oscore_cbor_get_next_element(const uint8_t **buffer, size_t *buf_len)
{
    return tsm_oscore_cbor_get_next_element(buffer, buf_len);
}

/* oscore_cbor_get_element_size returns
 *   - size of byte strings of character strings
 *   - size of array
 *   - size of map
 *   - value of unsigned integer
 */

size_t oscore_cbor_get_element_size(const uint8_t **buffer, size_t *buf_len)
{
    return tsm_oscore_cbor_get_element_size(buffer, buf_len);
}

uint8_t oscore_cbor_elem_contained(const uint8_t *data, size_t *buf_len, uint8_t *end)
{
    return tsm_oscore_cbor_elem_contained(data, buf_len, end);
}

int64_t oscore_cbor_get_negative_integer(const uint8_t **buffer, size_t *buf_len)
{
    return tsm_oscore_cbor_get_negative_integer(buffer, buf_len);
}

uint64_t oscore_cbor_get_unsigned_integer(const uint8_t **buffer, size_t *buf_len)
{
    return tsm_oscore_cbor_get_unsigned_integer(buffer, buf_len);
}

/*
 * oscore_cbor_get_number
 *
 * gets a negative or positive number from data
 * OK: return 0 ; NOK: return 1
 */
uint8_t oscore_cbor_get_number(const uint8_t **data, size_t *buf_len, int64_t *value)
{
    return tsm_oscore_cbor_get_number(data, buf_len, value) != TSM_OK;
}

/*
 * oscore_cbor_get_simple_value
 *
 * gets a simple value from data
 * OK: return 0 ; NOK: return 1
 */
uint8_t oscore_cbor_get_simple_value(const uint8_t **data, size_t *buf_len, uint8_t *value)
{
    return tsm_oscore_cbor_get_simple_value(data, buf_len, value) != TSM_OK;
}

void oscore_cbor_get_string(const uint8_t **buffer, size_t *buf_len, char *str, size_t size)
{
    tsm_oscore_cbor_get_string(buffer, buf_len, str, size);
}

void oscore_cbor_get_array(const uint8_t **buffer, size_t *buf_len, uint8_t *arr, size_t size)
{
    tsm_oscore_cbor_get_array(buffer, buf_len, arr, size);
}

/* oscore_cbor_get_string_array
 * fills the the size and the array from the cbor element
 */
uint8_t oscore_cbor_get_string_array(const uint8_t **data, size_t *buf_len, uint8_t **result,
                                     size_t *len)
{
    return tsm_oscore_cbor_get_string_array(data, buf_len, result, len) != TSM_OK;
}

/* oscore_cbor_strip value
 * strips the value of the cbor element into result
 *  and returns size
 */
uint8_t oscore_cbor_strip_value(const uint8_t **data, size_t *buf_len, uint8_t **result,
                                size_t *len)
{
    return tsm_oscore_cbor_strip_value(data, buf_len, result, len) != TSM_OK;
}

void oscore_log_hex_value(int level, const char *name, TSM_STR *value)
{
  tsm_oscore_log_hex_value(level, name, value);
}

void oscore_log_char_value(int level, const char *name, const char *value)
{
  tsm_oscore_log_char_value(level, name, value);
}

void cose_encrypt0_init(cose_encrypt0_t *ptr)
{
    tsm_cose_encrypt0_init(ptr);
}

void cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg)
{
    tsm_cose_encrypt0_set_alg(ptr, alg);
}

void cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size)
{
    tsm_cose_encrypt0_set_plaintext(ptr, buffer, size);
}

void cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size)
{
    tsm_cose_encrypt0_set_ciphertext(ptr, buffer, size);
}

/* Return length */
size_t cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, const uint8_t **buffer)
{
    return tsm_cose_encrypt0_get_key_id(ptr, buffer);
}

/* Return length */
size_t cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, const uint8_t **buffer)
{
    return tsm_cose_encrypt0_get_kid_context(ptr, buffer);
}

int cose_encrypt0_encrypt(cose_encrypt0_t *ptr, uint8_t *ciphertext_buffer, size_t ciphertext_len)
{
    return tsm_cose_encrypt0_encrypt(ptr, ciphertext_buffer, ciphertext_len);
}

int cose_encrypt0_decrypt(cose_encrypt0_t *ptr, uint8_t *plaintext_buffer, size_t plaintext_len)
{
    return tsm_cose_encrypt0_decrypt(ptr, plaintext_buffer, plaintext_len);
}

size_t oscore_encode_option_value(uint8_t *option_buffer,
                                  size_t option_buf_len,
                                  cose_encrypt0_t *cose,
                                  uint8_t group,
                                  uint8_t appendix_b_2)
{
  return tsm_oscore_encode_option_value(option_buffer, option_buf_len, cose, group, appendix_b_2);
}

/*
 * Decodes the OSCORE option value and places decoded values into the provided
 * cose structure */
int oscore_decode_option_value(const uint8_t *option_value,
                               size_t option_len,
                               cose_encrypt0_t *cose)
{
  return tsm_oscore_decode_option_value(option_value, option_len, cose) == TSM_OK;
}

size_t oscore_prepare_aad(const uint8_t *external_aad_buffer,
                          size_t external_aad_len,
                          uint8_t *aad_buffer,
                          size_t aad_size)
{
  return tsm_oscore_prepare_aad(external_aad_buffer, external_aad_len, aad_buffer, aad_size);
}

size_t oscore_prepare_e_aad(oscore_ctx_t *ctx,
                            cose_encrypt0_t *cose,
                            const uint8_t *oscore_option,
                            size_t oscore_option_len,
                            TSM_STR *sender_public_key,
                            uint8_t *external_aad_ptr,
                            size_t external_aad_size)
{
  return tsm_oscore_prepare_e_aad(ctx, cose, oscore_option, oscore_option_len, sender_public_key,
                                  external_aad_ptr, external_aad_size);
}

/* Creates Nonce */
void oscore_generate_nonce(cose_encrypt0_t *ptr, oscore_ctx_t *ctx, uint8_t *buffer, uint8_t size)
{
  tsm_oscore_generate_nonce(ptr, ctx, buffer, size);
}


uint8_t oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose)
{
    return tsm_oscore_validate_sender_seq(ctx, cose) == TSM_OK;
}

uint8_t oscore_increment_sender_seq(oscore_ctx_t *ctx)
{
  return tsm_oscore_increment_sender_seq(ctx) == TSM_OK;
}

void oscore_roll_back_seq(oscore_recipient_ctx_t *ctx)
{
  tsm_oscore_roll_back_seq(ctx);
}

const char *cose_get_alg_name(cose_alg_t id, char *buffer, size_t buflen)
{
  return tsm_cose_get_alg_name(id, buffer, buflen);
}

size_t cose_tag_len(cose_alg_t cose_alg)
{
  return tsm_cose_tag_len(cose_alg);
}
#endif /* COAP_OSCORE_SUPPORT */

#else /* !COAP_WITH_LIBTINYDTLS && !COAP_WITH_LIBOPENSSL && !COAP_WITH_LIBGNUTLS */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* !COAP_WITH_LIBTINYDTLS && !COAP_WITH_LIBOPENSSL && !COAP_WITH_LIBGNUTLS && !COAP_WITH_LIBMBEDTLS */
