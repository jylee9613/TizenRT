/****************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/
#include <tinyara/config.h>
#include <stdlib.h>
#include <sys/types.h>
#include <security/security_crypto.h>
#include "security_internal.h"

/**
 * Crypto
 */
security_error crypto_aes_encryption(security_handle hnd,
									 security_aes_param *param,
									 const char *key_name,
									 security_data *input,
									 security_data *output)
{
	if (!input || !input->data || !output) {
		SECAPI_RETURN(SECURITY_INVALID_INPUT_PARAMS);
	}

	security_error ret = SECURITY_OK;

	SECAPI_ENTER;
	SECAPI_ISHANDLE_VALID(hnd);
	struct security_ctx *ctx = (struct security_ctx *)hnd;

	HAL_INIT_AES_PARAM(hparam);
	SECAPI_CONVERT_AESPARAM(param, &hparam);

	// convert path
	uint32_t key_idx = 0;
	SECAPI_CONVERT_PATH(key_name, &key_idx);

	hal_data dec = {input->data, input->length, NULL, 0};
	hal_data enc = {ctx->data1, ctx->dlen1, NULL, 0};

	SECAPI_CALL3(sl_aes_encrypt(ctx->sl_hnd, &dec, &hparam, key_idx, &enc), SECURITY_ERROR, secutils_free_aeshparam(&hparam); secutils_free_hdata(&enc); secutils_free_hdata(&dec));

	output->data = (unsigned char *)malloc(enc.data_len);
	if (!output->data) {
		ret = SECURITY_ALLOC_ERROR;
		goto cleanup;
	}
	SECAPI_DATA_DCOPY(enc, output);
	ret = SECURITY_OK;

cleanup:
	/* Free hal data & param */
	secutils_free_aeshparam(&hparam);
	secutils_free_hdata(&enc);
	secutils_free_hdata(&dec);
	SECAPI_RETURN(ret);
}

security_error crypto_aes_decryption(security_handle hnd,
									 security_aes_param *param,
									 const char *key_name,
									 security_data *input,
									 security_data *output)
{
	if (!input || !input->data || !output) {
		SECAPI_RETURN(SECURITY_INVALID_INPUT_PARAMS);
	}

	security_error ret = SECURITY_OK;

	SECAPI_ENTER;
	SECAPI_ISHANDLE_VALID(hnd);
	struct security_ctx *ctx = (struct security_ctx *)hnd;

	HAL_INIT_AES_PARAM(hparam);
	SECAPI_CONVERT_AESPARAM(param, &hparam);

	// convert path
	uint32_t key_idx = 0;
	SECAPI_CONVERT_PATH(key_name, &key_idx);

	hal_data enc = {input->data, input->length, NULL, 0};
	hal_data dec = {ctx->data1, ctx->dlen1, NULL, 0};

	SECAPI_CALL3(sl_aes_decrypt(ctx->sl_hnd, &enc, &hparam, key_idx, &dec), SECURITY_ERROR, secutils_free_aeshparam(&hparam); secutils_free_hdata(&enc); secutils_free_hdata(&dec));
	
	output->data = (unsigned char *)malloc(dec.data_len);
	if (!output->data) {
		ret = SECURITY_ALLOC_ERROR;
		goto cleanup;
	}
	SECAPI_DATA_DCOPY(dec, output);
	ret = SECURITY_OK;

cleanup:
	/* Free hal data & param */
	secutils_free_aeshparam(&hparam);
	secutils_free_hdata(&enc);
	secutils_free_hdata(&dec);
	SECAPI_RETURN(ret);
}

security_error crypto_rsa_encryption(security_handle hnd,
									 security_rsa_param *param,
									 const char *key_name,
									 security_data *input,
									 security_data *output)
{
	if (!input || !input->data || !output) {
		SECAPI_RETURN(SECURITY_INVALID_INPUT_PARAMS);
	}

	security_error ret = SECURITY_OK;

	SECAPI_ENTER;
	SECAPI_ISHANDLE_VALID(hnd);
	struct security_ctx *ctx = (struct security_ctx *)hnd;

	HAL_INIT_RSA_PARAM(hmode);
	SECAPI_CONVERT_RSAPARAM(param, &hmode);

	/* convert path */
	uint32_t key_idx = 0;
	SECAPI_CONVERT_PATH(key_name, &key_idx);

	hal_data dec = {input->data, input->length, NULL, 0};
	hal_data enc = {ctx->data1, ctx->dlen1, NULL, 0};

	SECAPI_CALL3(sl_rsa_encrypt(ctx->sl_hnd, &dec, &hmode, key_idx, &enc), SECURITY_ERROR, secutils_free_hdata(&enc); secutils_free_hdata(&dec));
	
	output->data = (unsigned char *)malloc(enc.data_len);
	if (!output->data) {
		ret = SECURITY_ALLOC_ERROR;
		goto cleanup;
	}
	SECAPI_DATA_DCOPY(enc, output);
	ret = SECURITY_OK;

cleanup:
	/* Free hal data */
	secutils_free_hdata(&enc);
	secutils_free_hdata(&dec);
	SECAPI_RETURN(ret);
}

security_error crypto_rsa_decryption(security_handle hnd,
									 security_rsa_param *param,
									 const char *key_name,
									 security_data *input,
									 security_data *output)
{
	if (!input || !input->data || !output) {
		SECAPI_RETURN(SECURITY_INVALID_INPUT_PARAMS);
	}

	security_error ret = SECURITY_OK;

	SECAPI_ENTER;
	SECAPI_ISHANDLE_VALID(hnd);
	struct security_ctx *ctx = (struct security_ctx *)hnd;

	HAL_INIT_RSA_PARAM(hmode);
	SECAPI_CONVERT_RSAPARAM(param, &hmode);

	/* convert path */
	uint32_t key_idx = 0;
	SECAPI_CONVERT_PATH(key_name, &key_idx);

	hal_data enc = {input->data, input->length, NULL, 0};
	hal_data dec = {ctx->data1, ctx->dlen1, NULL, 0};

	SECAPI_CALL3(sl_rsa_decrypt(ctx->sl_hnd, &enc, &hmode, key_idx, &dec), SECURITY_ERROR, secutils_free_hdata(&enc); secutils_free_hdata(&dec));

	output->data = (unsigned char *)malloc(dec.data_len);
	if (!output->data) {
		ret = SECURITY_ALLOC_ERROR;
		goto cleanup;
	}
	SECAPI_DATA_DCOPY(dec, output);
	ret = SECURITY_OK;

cleanup:
	/* Free hal data */
	secutils_free_hdata(&enc);
	secutils_free_hdata(&dec);
	SECAPI_RETURN(ret);
}

security_error crypto_gcm_encryption(security_handle hnd,
									 security_gcm_param *param,
									 const char *key_name,
									 security_data *input,
									 security_data *output)
{
	if (!input || !input->data || !output) {
		SECAPI_RETURN(SECURITY_INVALID_INPUT_PARAMS);
	}

	security_error ret = SECURITY_OK;

	SECAPI_ENTER;
	SECAPI_ISHANDLE_VALID(hnd);
	struct security_ctx *ctx = (struct security_ctx *)hnd;

	HAL_INIT_GCM_PARAM(hparam);
	SECAPI_CONVERT_GCMPARAM(param, &hparam);

	// convert path
	uint32_t key_idx = 0;
	SECAPI_CONVERT_PATH(key_name, &key_idx);

	hal_data dec = {input->data, input->length, NULL, 0};
	hal_data enc = {ctx->data1, ctx->dlen1, NULL, 0};

	SECAPI_CALL3(sl_gcm_encrypt(ctx->sl_hnd, &dec, &hparam, key_idx, &enc), SECURITY_ERROR, secutils_free_gcmhparam(&hparam); secutils_free_hdata(&enc); secutils_free_hdata(&dec););

	/* Copy hal tag to framework tag */
	param->tag = (unsigned char *)malloc(hparam.tag_len);
	if (!param->tag) {
		ret = SECURITY_ALLOC_ERROR;
		goto cleanup;
	}
	
	output->data = (unsigned char *)malloc(enc.data_len);
	if (!output->data) {
		ret = SECURITY_ALLOC_ERROR;
		goto cleanup;
	}
	
	memcpy(param->tag, hparam.tag, hparam.tag_len);
	param->tag_len = hparam.tag_len;
	SECAPI_DATA_DCOPY(enc, output);
	ret = SECURITY_OK;

cleanup:
	/* Free hal data & param */
	security_free_hdata(&dec);
	security_free_hdata(&enc);
	secutils_free_gcmhparam(&hparam);
	SECAPI_RETURN(ret);
}

security_error crypto_gcm_decryption(security_handle hnd,
									 security_gcm_param *param,
									 const char *key_name,
									 security_data *input,
									 security_data *output)
{
	if (!input || !input->data || !output) {
		SECAPI_RETURN(SECURITY_INVALID_INPUT_PARAMS);
	}

	security_error ret = SECURITY_OK;

	SECAPI_ENTER;
	SECAPI_ISHANDLE_VALID(hnd);
	struct security_ctx *ctx = (struct security_ctx *)hnd;

	HAL_INIT_GCM_PARAM(hparam);
	SECAPI_CONVERT_GCMPARAM(param, &hparam);

	// convert path
	uint32_t key_idx = 0;
	SECAPI_CONVERT_PATH(key_name, &key_idx);

	hal_data enc = {input->data, input->length, NULL, 0};
	hal_data dec = {ctx->data1, ctx->dlen1, NULL, 0};

	SECAPI_CALL3(sl_gcm_decrypt(ctx->sl_hnd, &enc, &hparam, key_idx, &dec), SECURITY_ERROR, secutils_free_gcmhparam(&hparam); secutils_free_hdata(&enc); secutils_free_hdata(&dec););
	
	output->data = (unsigned char *)malloc(dec.data_len);
	if (!output->data) {
		ret = SECURITY_ALLOC_ERROR;
		goto cleanup;
	}
	SECAPI_DATA_DCOPY(dec, output);
	ret = SECURITY_OK;
	
cleanup:
	/* Free hal data & param */
	security_free_hdata(&dec);
	security_free_hdata(&enc);
	secutils_free_gcmhparam(&hparam);
	SECAPI_RETURN(ret);
}
