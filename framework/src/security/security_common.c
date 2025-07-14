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
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <tinyara/seclink.h>
#include <security/security_common.h>
#include "security_internal.h"

/**
 * Common
 */
security_error security_init(security_handle *hnd)
{
	SECAPI_ENTER;

	if (hnd == NULL) {
		SECAPI_RETURN(SECURITY_INVALID_INPUT_PARAMS);
	}

	struct security_ctx *ctx = (struct security_ctx *)malloc(sizeof(struct security_ctx));
	if (!ctx) {
		SECAPI_RETURN(SECURITY_ALLOC_ERROR);
	}

	SECAPI_CALL3(sl_init(&(ctx->sl_hnd)), SECURITY_ERROR, free(ctx));

	ctx->data1 = (char *)malloc(SECURITY_MAX_BUF);
	if (!ctx->data1) {
		sl_deinit(ctx->sl_hnd);
		free(ctx);
		SECAPI_RETURN(SECURITY_ALLOC_ERROR);
	}
	ctx->dlen1 = SECURITY_MAX_BUF;

	ctx->data2 = (char *)malloc(SECURITY_MAX_BUF);
	if (!ctx->data2) {
		sl_deinit(ctx->sl_hnd);
		free(ctx->data1);
		free(ctx);
		SECAPI_RETURN(SECURITY_ALLOC_ERROR);
	}
	ctx->dlen2 = SECURITY_MAX_BUF;

	*hnd = ctx;

	SECAPI_RETURN(SECURITY_OK);
}

security_error security_deinit(security_handle hnd)
{
	SECAPI_ENTER;
	SECAPI_ISHANDLE_VALID(hnd);

	struct security_ctx *ctx = (struct security_ctx *)hnd;
	sl_deinit(ctx->sl_hnd);

	free(ctx->data2);
	free(ctx->data1);
	free(ctx);

	SECAPI_RETURN(SECURITY_OK);
}

security_error security_free_data(security_data *data)
{
	if (data) {
		if (data->data) {
			free(data->data);
		}
		data->data = NULL;
		data->length = 0;
	} else {
		return SECURITY_INVALID_INPUT_PARAMS;
	}

	SECAPI_RETURN(SECURITY_OK);
}

security_error security_get_status(int *status)
{
	SECAPI_ENTER;
	if (!status) {
		SECAPI_RETURN(SECURITY_INVALID_INPUT_PARAMS);
	}
	//todo
	*status = 0;

	SECAPI_RETURN(SECURITY_OK);
}

security_error security_free_aes_param(security_aes_param *param)
{
	if (param->iv) {
		free(param->iv);
	}
	param->iv = NULL;
	param->iv_len = 0;

	SECAPI_RETURN(SECURITY_OK);
}

security_error security_free_gcm_param(security_gcm_param *param)
{
	if (param->iv) {
		free(param->iv);
	}
	param->iv = NULL;
	param->iv_len = 0;

	if (param->aad) {
		free(param->aad);
	}
	param->aad = NULL;
	param->aad_len = 0;

	if (param->tag) {
		free(param->tag);
	}
	param->tag = NULL;
	param->tag_len = 0;

	SECAPI_RETURN(SECURITY_OK);
}

security_error security_free_dh_param(security_dh_param *param)
{
	if (param->G) {
		free(param->G);
	}
	param->G = NULL;

	if (param->P) {
		free(param->P);
	}
	param->P = NULL;

	if (param->pubkey) {
		free(param->pubkey);
	}
	param->pubkey = NULL;

	SECAPI_RETURN(SECURITY_OK);
}

security_error security_free_ecdh_param(security_ecdh_param *param)
{
	if (param->pubkey_x) {
		free(param->pubkey_x);
	}
	param->pubkey_x = NULL;

	if (param->pubkey_y) {
		free(param->pubkey_y);
	}
	param->pubkey_y = NULL;

	SECAPI_RETURN(SECURITY_OK);
}
