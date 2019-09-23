/*
 * Copyright (c) 2013 Jan-Piet Mens <jp@mens.de>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions
 * in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. Neither the name of mosquitto
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef BE_SQLITE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "backends.h"
#include "be-sqlite.h"
#include "hash.h"
#include "log.h"
#include <mosquitto.h>

static bool prepareStatement(struct sqlite_backend *conf, struct stmt_query *stmt)
{
	bool ret;
	ret = sqlite3_prepare(conf->sq, stmt->query, stmt->query_length, &stmt->stmt, NULL) == SQLITE_OK;
	if (!ret)
		_log(MOSQ_LOG_WARNING, "Can't prepare: %s\n", sqlite3_errmsg(conf->sq));
	return ret;
}

void *be_sqlite_init()
{
	struct sqlite_backend *conf;
	int flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_SHAREDCACHE;
	char *dbpath, *userquery, *aclquery;

	if ((dbpath = p_stab("dbpath")) == NULL) {
		_fatal("Mandatory parameter `dbpath' missing");
		return (NULL);
	}
	if ((userquery = p_stab("sqliteuserquery")) == NULL) {
		_fatal("Mandatory parameter `sqliteuserquery' missing");
		return (NULL);
	}
	aclquery = p_stab("sqliteaclquery");

	conf = (struct sqlite_backend *)malloc(sizeof(struct sqlite_backend));

	if (sqlite3_open_v2(dbpath, &conf->sq, flags, NULL) != SQLITE_OK) {
		_log(MOSQ_LOG_ERR, "failed to open: %s", dbpath);
		free(conf);
		return (NULL);
	}

	conf->user = NULL;
	if(userquery) {
		conf->user = (struct stmt_query *)malloc(sizeof(struct stmt_query));
		conf->user->stmt = NULL;
		conf->user->query = userquery;
		conf->user->query_length = strlen(userquery);
		prepareStatement(conf,conf->user);
	}

	conf->acl = NULL;
	if(aclquery) {
		conf->acl = (struct stmt_query *)malloc(sizeof(struct stmt_query));
		conf->acl->stmt = NULL;
		conf->acl->query = aclquery;
		conf->acl->query_length = strlen(aclquery);
		prepareStatement(conf,conf->acl);
	}
	
	return (conf);
}

void be_sqlite_destroy(void *handle)
{
	struct sqlite_backend *conf = (struct sqlite_backend *)handle;

	if (conf) {
		if (conf->acl) {
			if (conf->acl->stmt) {
				 sqlite3_finalize(conf->acl->stmt);
			}
			free(conf->acl);
		}
		if (conf->user) {
			if (conf->user->stmt) {
				sqlite3_finalize(conf->user->stmt);
			}
			free(conf->user);
		} 
		sqlite3_close(conf->sq);
		free(conf);
	}
}

int be_sqlite_getuser(void *handle, const char *username, const char *password, char **phash, const char *clientid)
{
	struct sqlite_backend *conf = (struct sqlite_backend *)handle;
	int res, retries;
	char *value = NULL, *v;
	int result = BACKEND_DEFER;

	if (!conf || !conf->user)
		return BACKEND_DEFER;

	for (retries = 5; --retries > 0 && value == NULL;) {
		if (conf->user->stmt == NULL)
			if (!prepareStatement(conf,conf->user))
				return BACKEND_ERROR;

		res = sqlite3_reset(conf->user->stmt);
		if (res != SQLITE_OK) {
			_log(MOSQ_LOG_ERR, "statement reset: %s", sqlite3_errmsg(conf->sq));
			result = BACKEND_ERROR;
			goto out;
		}
		res = sqlite3_clear_bindings(conf->user->stmt);
		if (res != SQLITE_OK) {
			_log(MOSQ_LOG_ERR, "bindings clear: %s", sqlite3_errmsg(conf->sq));
			result = BACKEND_ERROR;
			goto out;
		}
		res = sqlite3_bind_text(conf->user->stmt, 1, username, -1, SQLITE_STATIC);
		if (res != SQLITE_OK) {
			_log(MOSQ_LOG_ERR, "Can't bind: %s", sqlite3_errmsg(conf->sq));
			result = BACKEND_ERROR;
			goto out;
		}
		res = sqlite3_step(conf->user->stmt);

		switch (res) {
		case SQLITE_ROW:
			v = (char *)sqlite3_column_text(conf->user->stmt, 0);
			if (v)
				value = strdup(v);
			break;
		case SQLITE_ERROR:
			sqlite3_finalize(conf->user->stmt);
			conf->user->stmt = NULL;
			result = BACKEND_ERROR;
			break;
		default:
			_log(MOSQ_LOG_ERR, "step: %s", sqlite3_errmsg(conf->sq));
			break;
		}
	}

out:
	sqlite3_reset(conf->user->stmt);

	*phash = value;
	return result;
}

int be_sqlite_superuser(void *handle, const char *username)
{
	return BACKEND_DEFER;
}

int be_sqlite_aclcheck(void *handle, const char *clientid, const char *username, const char *topic, int acc)
{
	struct sqlite_backend *conf = (struct sqlite_backend *)handle;
	int res;
	char *v;
	int result = BACKEND_DEFER;
	bool bf;

	if (!conf)
		return BACKEND_DEFER;

	if (!conf->acl)
		return BACKEND_ALLOW;

	if (conf->acl->stmt == NULL)
		if (!prepareStatement(conf,conf->acl))
			return BACKEND_ERROR;

	res = sqlite3_reset(conf->acl->stmt);
	if (res != SQLITE_OK) {
		_log(MOSQ_LOG_ERR, "statement reset: %s", sqlite3_errmsg(conf->sq));
		result = BACKEND_ERROR;
		goto out;
	}
	res = sqlite3_clear_bindings(conf->acl->stmt);
	if (res != SQLITE_OK) {
		_log(MOSQ_LOG_ERR, "bindings clear: %s", sqlite3_errmsg(conf->sq));
		result = BACKEND_ERROR;
		goto out;
	}
	res = sqlite3_bind_text(conf->acl->stmt, 1, username, -1, SQLITE_STATIC);
	if (res != SQLITE_OK) {
		_log(MOSQ_LOG_ERR, "Can't bind: %s", sqlite3_errmsg(conf->sq));
		result = BACKEND_ERROR;
		goto out;
	}
	res = sqlite3_bind_int(conf->acl->stmt, 2, acc);
	if (res != SQLITE_OK) {
		_log(MOSQ_LOG_ERR, "Can't bind: %s", sqlite3_errmsg(conf->sq));
		result = BACKEND_ERROR;
		goto out;
	}

	while (result == BACKEND_DEFER && (res = sqlite3_step(conf->acl->stmt)) == SQLITE_ROW) {
		if ((v = (char *)sqlite3_column_text(conf->acl->stmt, 0)) != NULL) {

			/*
			* Check mosquitto_match_topic. If bf is true, set
			* result and break out of loop.
			*/

			char *expanded;

			t_expand(clientid, username, v, &expanded);
			if (expanded && *expanded) {
				mosquitto_topic_matches_sub(expanded, topic, &bf);
				if (bf) 
					result = BACKEND_ALLOW;
				_log(LOG_DEBUG, "  sqlite: topic_matches(%s, %s) == %d", expanded, v, bf);
				free(expanded);
			}
		}
	}

	if(res == SQLITE_ERROR){
		sqlite3_finalize(conf->acl->stmt);
		conf->acl->stmt = NULL;
		result = BACKEND_ERROR;
	}

out:
	sqlite3_reset(conf->acl->stmt);
	return result;
}
#endif /* BE_SQLITE */
