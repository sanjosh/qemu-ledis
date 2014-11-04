/*
 * QEMU Block driver for  LedisDB
 *
 * Copyright (C) 2014 
 *     Author: Sandeep Joshi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/uri.h"
#include "block/block_int.h"
#include "qemu/module.h"
#include "qemu/sockets.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qint.h"
#include "qapi/qmp/qstring.h"

#include "hiredis/hiredis.h"

#include "NonAlignedCopy.h"
#include "qemu/crc32c.h"

#include "ldb_crypto.h"
#include "ldb_md5.h"

#include <sys/types.h>
#include <unistd.h>

#define METASERVICE 1000 // should go into QemuOpts
#define METAPORT 100

#define DATASERVICE 2000
#define DATAPORT 100

#define TRACE(msg, ...) do { \
    LOG(msg, ## __VA_ARGS__); \
    } while (0)

#define LOG(msg, ...) do { \
    fprintf(stderr, "%s:%s():L%d: " msg "\n", \
    __FILE__, __FUNCTION__, __LINE__, ## __VA_ARGS__); \
    } while (0)

typedef struct Connection
{
    redisContext* context;
    int service;
    int port;
	int64_t missingReads;
	int64_t reads;
	int64_t writes;
} Connection;

typedef struct LDBState {
    Connection data; 
    Connection meta; 
    int64_t readModifyWrites;
} LDBState;

#define MD5_LEN 16
typedef char MD5_t[MD5_LEN];

#define SECTOR_SIZE (512)
#define LDB_BLKSIZE (4096)
#define BLOCK_NUMBER(off) (off/4096)

static int ldb_parse_uri(const char *filename, QDict *dict)
{
    URI *uri;
    QueryParams *qp = NULL;
    int ret = 0;

    uri = uri_parse(filename);
    if (!uri) {
        return -EINVAL;
    }

    // transport 
    if (strcmp(uri->scheme, "ldb") != 0) {
        ret = -EINVAL;
        goto out;
    }

    qp = query_params_parse(uri->query);
    if (qp->n > 1) {
        ret = -EINVAL;
        goto out;
    }

    {
        if ((!uri->server) || (!uri->port)) {
            ret = -EINVAL;
            goto out;
        }
        
        QString* host = qstring_from_str(uri->server);
        qdict_put(dict, "host", host);

        char* port_str = g_strdup_printf("%d", uri->port);
        qdict_put(dict, "port", qstring_from_str(port_str));
        g_free(port_str);
    }

out:
    if (qp) {
        query_params_free(qp);
    }
    uri_free(uri);
    return ret;
}

static void ldb_parse_filename(const char *filename, QDict *dict,
                               Error **errp)
{
    char *file;
    const char *host_spec;

    if (strstr(filename, "://")) {
        int ret = ldb_parse_uri(filename, dict);
        if (ret < 0) {
            error_setg(errp, "No valid URL specified");
        }
        return;
    }

    file = g_strdup(filename);

    // extract the host_spec - fail if it's not ldb:... 
    if (!strstart(file, "ldb:", &host_spec)) {
        error_setg(errp, "File name string for LDB must start with 'ldb:'");
        goto out;
    }

    if (!*host_spec) {
        goto out;
    }

    {
        InetSocketAddress* addr = inet_parse(host_spec, errp);

        if (!addr) {
            goto out;
        }

        qdict_put(dict, "host", qstring_from_str(addr->host));
        qdict_put(dict, "port", qstring_from_str(addr->port));
        qapi_free_InetSocketAddress(addr);
    }

out:
    g_free(file);
}

static int ldb_establish_connection(BlockDriverState *bs, Error** errp)
{
    LDBState *s = bs->opaque;

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds

    s->data.context = redisConnectTIPCWithTimeout(s->data.service, s->data.port, timeout);

    if (s->data.context == NULL || s->data.context->err) 
    {
        if (s->data.context) 
        {
            error_setg_errno(errp, -ENOTCONN, "Connection error to data server: %s", s->data.context->errstr);
            redisFree(s->data.context);
        } 
        else 
        {
            error_setg_errno(errp, -ENOTCONN, "Connection error: can't allocate redis context\n");
        }
        return -ENOTCONN;
    }

    s->meta.context = redisConnectTIPCWithTimeout(s->meta.service, s->meta.port, timeout);

    if (s->meta.context == NULL || s->meta.context->err) 
    {
        if (s->meta.context) 
        {
            error_setg_errno(errp, -ENOTCONN, "Connection error to meta server: %s", s->meta.context->errstr);
            redisFree(s->meta.context);
        } 
        else 
        {
            error_setg_errno(errp, -ENOTCONN, "Connection error: can't allocate redis context\n");
        }

        redisFree(s->data.context);
        return -ENOTCONN;
    }

    // Send Ping to LDB and get Pong back 
    //result = ldb_client_session_init(&s->client, bs, sock, export);
    //g_free(export);


    return 0;
}

static QemuOptsList runtime_opts = {
    .name = "ldb",  
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "LDB image name", 
        },
        { /* end of list */ }
    },
};

static void ldb_config(LDBState* s, QDict* dict, Error** errp)
{
    Error* local_err = NULL;

    QemuOpts* opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);

    qemu_opts_absorb_qdict(opts, dict, &local_err);

    const char* hostname = qemu_opt_get(opts, "host");
    if (hostname) {
        s->data.service = atoi(hostname);
    } else {
        s->data.service = DATASERVICE;
    }

    const char* portname = qemu_opt_get(opts, "port");
    if (portname) {
        s->data.port = atoi(portname);
    } else {
        s->data.port = DATAPORT;
    }
    
    s->meta.service = METASERVICE;
    s->meta.port = METAPORT;

    qemu_opts_del(opts);
    qdict_del(dict, "host");
    qdict_del(dict, "port");
}

static int ldb_open(BlockDriverState *bs, QDict *dict, int flags,
                    Error **errp)
{
    LDBState *s = bs->opaque;

    s->data.reads = s->data.writes = s->data.missingReads = 0;
    s->meta.reads = s->meta.writes = s->meta.missingReads = 0;
    s->readModifyWrites = 0;

    ldb_config(s, dict, errp);

    int ret = ldb_establish_connection(bs, errp);

    LOG("opened connection with ret=%d\n", ret);
    return ret;
}

// ============================

int DataSetCmdAsync(LDBState* s, MD5_t md5, const char* buffer);
int DataSetReplyAsync(LDBState* s);
int DataGetCmd(LDBState* s, MD5_t md5, char* buffer);
int DataGetCmdAsync(LDBState* s, MD5_t md5);
int DataGetReplyAsync(LDBState* s, char* buffer, ssize_t startOffset, ssize_t bufferSize);
int MetaSetCmdAsync(LDBState* s, ssize_t offset, MD5_t md5);
int MetaSetReplyAsync(LDBState* s);
int MetaGetCmd(LDBState* s, ssize_t offset, MD5_t md5);
int MetaGetCmdAsync(LDBState* s, ssize_t offset);
int MetaGetReplyAsync(LDBState* s, MD5_t md5);

int DataSetCmdAsync(LDBState* s, MD5_t md5, const char* buffer)
{
    int localResult  = redisAppendCommand(s->data.context, "SETNX %b %b", md5, MD5_LEN, buffer, LDB_BLKSIZE);

    if (localResult != REDIS_OK)
    {
        error_report("SET command issue error: %d\n", localResult);
        return -EIO;
    }
    return 0;
}

int DataSetReplyAsync(LDBState* s)
{
    redisReply* reply = NULL;

    redisGetReply(s->data.context, (void**)&reply);
    if (reply->type == REDIS_REPLY_ERROR)
    {
        error_report("SET error: %s %d %s\n", reply->str, s->data.context->err, s->data.context->errstr);
        return -EIO;
    }
    //freeReplyObject(reply);
	s->data.writes ++;
    return 0;
}

int DataGetCmd(LDBState* s, MD5_t md5, char* buffer)
{
	redisReply* reply = redisCommand(s->data.context, "GET %b", md5, MD5_LEN);

	if (reply->type == REDIS_REPLY_ERROR)
	{
        error_report("GET error: %s %d %s\n", reply->str, s->data.context->err, s->data.context->errstr);
		return -EIO;
	}
	else if ((reply->type == REDIS_REPLY_NIL) || (reply->type == REDIS_REPLY_STATUS))
	{
		return -ENOENT;
	}
	else
	{
		assert (reply->len == LDB_BLKSIZE);
		assert (reply->type == REDIS_REPLY_STRING);
		s->data.reads ++;

		memcpy(buffer, reply->str, reply->len);
		return 0;
	}
    assert("dont come here" == 0);
}

int DataGetCmdAsync(LDBState* s, MD5_t md5)
{
    int localResult  = redisAppendCommand(s->data.context, "GET %b", md5, MD5_LEN);

    if (localResult != REDIS_OK)
    {
        error_report("GET command issue error: %d\n", localResult);
        return -EIO;
    }
    return 0;
}

int DataGetReplyAsync(LDBState* s, char* buffer, ssize_t startOffset, ssize_t bufferSize)
{
    redisReply* reply = NULL;
    redisGetReply(s->data.context, (void**)&reply);

    if (reply->type == REDIS_REPLY_ERROR)
    {
        error_report("GET error: %s %d %s\n", reply->str, s->data.context->err, s->data.context->errstr);
        return -EIO;
    }
    else
    {
        if (reply->type == REDIS_REPLY_NIL)
        {
            // block was never written - no md5 exists for offset
			s->data.missingReads ++;
            return -ENOENT;
        }
        else
        {
			s->data.reads ++;
            assert(reply->len == LDB_BLKSIZE);
            assert(reply->len >= bufferSize);
            assert(startOffset < LDB_BLKSIZE);
            assert (reply->type == REDIS_REPLY_STRING);
            memcpy(buffer, reply->str + startOffset, bufferSize);
            return 0;
        }
    }
    assert("dont come here" == 0);
}

int MetaSetCmdAsync(LDBState* s, ssize_t offset, MD5_t md5)
{
    char dataCmd[100];
    sprintf(dataCmd, "%lu", BLOCK_NUMBER(offset));

    int localResult = redisAppendCommand(s->meta.context, "SET %b %b", dataCmd, strlen(dataCmd), md5, MD5_LEN);

    if (localResult != REDIS_OK)
    {
        error_report("Write command issue error: %d\n", localResult);
        return -EIO;
    }
    return 0;
}

int MetaSetReplyAsync(LDBState* s)
{
    redisReply* reply = NULL;

    redisGetReply(s->meta.context, (void**)&reply);
    if (reply->type == REDIS_REPLY_ERROR)
    {
        error_report("Write error: %s %d %s\n", reply->str, s->meta.context->err, s->meta.context->errstr);
        return -EIO;
    }
    //freeReplyObject(reply);
	s->meta.writes ++;
    return 0;
}

int MetaGetCmd(LDBState* s, ssize_t offset, MD5_t md5)
{
	char query[100];
	sprintf(query, "GET %lu", BLOCK_NUMBER(offset));

	redisReply* reply = redisCommand(s->meta.context, query);

	if (reply->type == REDIS_REPLY_ERROR)
	{
        error_report("Read error: %s %d %s\n", reply->str, s->meta.context->err, s->meta.context->errstr);
		return -EIO;
	}
	else if ((reply->type == REDIS_REPLY_NIL) || (reply->type == REDIS_REPLY_STATUS))
	{
		s->meta.missingReads ++;
		return -ENOENT;
	}
	else
	{
		s->meta.reads ++;
		assert (reply->len == MD5_LEN);
		assert (reply->type == REDIS_REPLY_STRING);

		memcpy(md5, reply->str, reply->len);
		return 0;
	}
}

int MetaGetCmdAsync(LDBState* s, ssize_t offset)
{
    char query[100];
    sprintf(query, "GET %lu", BLOCK_NUMBER(offset));

    int localResult  = redisAppendCommand(s->meta.context, query);

    if (localResult != REDIS_OK)
    {
        error_report("Read command issue error: %d\n", localResult);
        return -EIO;
    }
    return 0;
}

int MetaGetReplyAsync(LDBState* s, MD5_t md5)
{
    redisReply* reply = NULL;
    redisGetReply(s->meta.context, (void**)&reply);

    if (reply->type == REDIS_REPLY_ERROR)
    {
        error_report("Read error: %s %d %s\n", reply->str, s->meta.context->err, s->meta.context->errstr);
        //freeReplyObject(reply);
        return -EIO;
    }
	else if (reply->type == REDIS_REPLY_NIL)
	{
		// block was never written - no md5 exists for offset
		s->meta.missingReads ++;
		return -ENOENT;
	}
	else
	{
		s->meta.reads ++;
		assert(reply->len == MD5_LEN);
		assert (reply->type == REDIS_REPLY_STRING);

		memcpy(md5, reply->str, reply->len);
		return 0;
	}
    assert("dont come here" == 0);
}

// ============================

/*
 *  MetaData : key=offset, value=md5
 *  Data     : key=md5, value=buffer
 */
static int ldb_read(BlockDriverState *bs, int64_t sector_num,
    uint8_t *buf, int nb_sectors)
{
    LDBState *s = bs->opaque;
    int result = 0;

    /* 
        md5 = control->get(block)
        if (md5)
            buffer = data->get(md5)
            memcpy(newbuf, buffer, 4k)
        else
            bzero(newbuf, 4k)
    */

    const size_t blocksToReadSz = ((nb_sectors/8) + 2);
    char* blocksToRead = (char*)malloc(blocksToReadSz);
    bzero(blocksToRead, blocksToReadSz);

    NonAlignedCopy a;
    NonAlignedCopyInit(&a, sector_num * SECTOR_SIZE, nb_sectors * SECTOR_SIZE, LDB_BLKSIZE);

    while (NonAlignedCopyIsValid(&a))
    {
        ssize_t retOff = 0;
        ssize_t retSz = 0;
        NonAlignedCopyNext(&a, &retOff, &retSz);

        if (retSz != LDB_BLKSIZE)
        {
            //LOG("less than 4k read at sector=%lu %d retoff=%lu siz=%lu\n", sector_num, nb_sectors, retOff, retSz);
        }

        int localResult = MetaGetCmdAsync(s, retOff);

        if (localResult != 0)
        {
            result = -EIO;
            break;
        }
    }
    
    if (result != 0)
    {
        return result;
    }

    NonAlignedCopyInit(&a, sector_num * SECTOR_SIZE, nb_sectors * SECTOR_SIZE, LDB_BLKSIZE);

    int blocksIndex = 0;

    while (NonAlignedCopyIsValid(&a))
    {
        ssize_t retOff = 0;
        ssize_t retSz = 0;
        NonAlignedCopyNext(&a, &retOff, &retSz);

        MD5_t md5;
        
        int localResult = MetaGetReplyAsync(s, md5);
    
        if (localResult == 0)
        {
            // fetch the block from data server
            blocksToRead[blocksIndex] = '1';

            DataGetCmdAsync(s, md5);
            //uint32_t crc = crc32c(0xffffffff, (uint8_t*)reply->str, reply->len);
            //LOG("read at blk=%lu reqsiz=%ld actual=%d checksum=%u\n", BLOCK_NUMBER(retOff), retSz, reply->len, crc);
        }
		else if (localResult == -ENOENT)
        {
        }
    	else
	    {
            result = -EIO;
            break;
        }

        //freeReplyObject(reply);
        blocksIndex ++;
    }

    if (result != 0)
    {
        return result;
    }

    NonAlignedCopyInit(&a, sector_num * SECTOR_SIZE, nb_sectors * SECTOR_SIZE, LDB_BLKSIZE);

    blocksIndex = 0;

    while (NonAlignedCopyIsValid(&a))
    {
        ssize_t retOff = 0;
        ssize_t retSz = 0;
        NonAlignedCopyNext(&a, &retOff, &retSz);

        ssize_t relativeOff = retOff - (sector_num * SECTOR_SIZE);
        assert(relativeOff < nb_sectors * SECTOR_SIZE);
        uint8_t* curBuf = buf + relativeOff;

		if (blocksToRead[blocksIndex] != '1')
        {
          	bzero(curBuf, retSz);
        }
        else
        {
            ssize_t startOffset = retOff % LDB_BLKSIZE; // if retOff is not 4k-aligned, memcpy has to be done in middle of buffer

            int localResult = DataGetReplyAsync(s, (char*) curBuf, startOffset, retSz);

            //uint32_t crc = crc32c(0xffffffff, (uint8_t*)reply->str, reply->len);
            //LOG("read at blk=%lu reqsiz=%ld actual=%d checksum=%u\n", BLOCK_NUMBER(retOff), retSz, reply->len, crc);

            if (localResult != 0)
            {
                result = -EIO;
                break;
            }
            //freeReplyObject(reply);
        }
        blocksIndex ++;
    }

    free(blocksToRead);

    return 0;
}

void computeMD5(const char* buffer, MD5_t md5);

void computeMD5(const char* buffer, MD5_t md5)
{
    struct md5_ctx ctx;
    digest_init(&md5_algorithm, &ctx);

    digest_update(&md5_algorithm, &ctx, buffer, LDB_BLKSIZE);

    digest_final(&md5_algorithm, &ctx, md5);
}

static int ldb_write(BlockDriverState *bs, int64_t sector_num,
    const uint8_t *buf, int nb_sectors)
{
    LDBState *s = bs->opaque;
    int result = 0;

    /* 
        If partial 4k write
            md5 = control->get(block)
            if (md5)
                buffer = data->get(md5)
                memcpy(newbuf, buffer, 4k)
                memcpy(newbuf, curbuf, wherever)
            else
                bzero(newbuf, 4k)
                memcpy(newbuf, curbuf, wherever)
       else
            Delete old md5 from data server (if ref count == 1)
        Compute new_md5 for newbuf
        data->setnx(new_md5, newbuf)
        control->set(block, new_md5)
    */

    NonAlignedCopy a;
    NonAlignedCopyInit(&a, sector_num * SECTOR_SIZE, nb_sectors * SECTOR_SIZE, LDB_BLKSIZE);

    while (NonAlignedCopyIsValid(&a))
    {
        ssize_t retOff = 0;
        ssize_t retSz = 0;
        NonAlignedCopyNext(&a, &retOff, &retSz);

        ssize_t relativeOff = retOff - (sector_num * SECTOR_SIZE);
        assert(relativeOff < nb_sectors * SECTOR_SIZE);
        const uint8_t* curBuf = buf + relativeOff;

		const uint8_t* actualBuf = curBuf;

        if (retSz != LDB_BLKSIZE)
        {
            //LOG("less than 4k write at sector=%lu %d retoff=%lu siz=%lu\n", sector_num, nb_sectors, retOff, retSz);

	   		actualBuf = (const uint8_t*)malloc(LDB_BLKSIZE);
			bzero((char*)actualBuf, LDB_BLKSIZE);

			MD5_t md5;	
			int localResult = MetaGetCmd(s, retOff, md5);

			if (localResult == 0)
			{
				// overlay old block, if any, onto the new block
				localResult = DataGetCmd(s, md5, (char*)actualBuf);
				assert(localResult == 0);
				//LOG("RMW done at blk=%lu siz=%lu \n", BLOCK_NUMBER(retOff), retSz);
				s->readModifyWrites ++;
			}

			// current write may not start at 4K boundary
			memcpy((char*)actualBuf + (retOff % LDB_BLKSIZE), curBuf, retSz);
        }

        //Compute new_md5 for newbuf
        MD5_t newmd5;
        computeMD5((const char*)actualBuf, newmd5);

        //data->setnx(new_md5, newbuf)
        int localResult = DataSetCmdAsync(s, newmd5, (const char*)actualBuf);
        if (localResult != 0)
        {
            result = -EIO;
            break;
        }

        //control->set(block, new_md5)
        localResult = MetaSetCmdAsync(s, retOff, newmd5);
        if (localResult != 0)
        {
            result = -EIO;
            break;
        }

        //uint32_t crc = crc32c(0xffffffff, actualBuf, LDB_BLKSIZE);
        //LOG("write at blk=%lu siz=%lu checksum=%u\n", BLOCK_NUMBER(retOff), retSz, crc);

		if (retSz != LDB_BLKSIZE)
		{
			free((char*)actualBuf);
		}
    }
    
    if (result != 0)
    {
        return result;
    }

    NonAlignedCopyInit(&a, sector_num * SECTOR_SIZE, nb_sectors * SECTOR_SIZE, LDB_BLKSIZE);

    while (NonAlignedCopyIsValid(&a))
    {
        ssize_t retOff;
        ssize_t retSz;
        NonAlignedCopyNext(&a, &retOff, &retSz);

        int localResult = MetaSetReplyAsync(s);
        if (localResult != 0)
        {
            result = -EIO;
            break;
        }

        localResult = DataSetReplyAsync(s);
        if (localResult != 0)
        {
            result = -EIO;
            break;
        }
        //freeReplyObject(reply);
    }

    return result;
}

/*
static int ldb_co_readv(BlockDriverState *bs, int64_t sector_num,
                        int nb_sectors, QEMUIOVector *qiov)
{
    //LDBState *s = bs->opaque;

    //return ldb_client_session_co_readv(&s->client, sector_num,
                                       //nb_sectors, qiov);
}

static int ldb_co_writev(BlockDriverState *bs, int64_t sector_num,
                         int nb_sectors, QEMUIOVector *qiov)
{
    LDBState *s = bs->opaque;

    return ldb_client_session_co_writev(&s->client, sector_num,
                                        nb_sectors, qiov);
}
*/

/*
nbd.c write sync
if (qemu_in_coroutine())
{
    return qemu_co_send(fd, buffer, size); 
    // qemu-common.h, qemu-coroutine-io.c
}

while (offset < size)
{
    read :qemu_recv(fd, buffer, size, 0)
    write:send(fd, buffer, size, 0)
}

static int ldb_co_flush(BlockDriverState *bs)
{
    LDBState *s = bs->opaque;

    return ldb_client_session_co_flush(&s->client);
}

static int ldb_co_discard(BlockDriverState *bs, int64_t sector_num,
                          int nb_sectors)
{
    LDBState *s = bs->opaque;

    return ldb_client_session_co_discard(&s->client, sector_num,
                                         nb_sectors);
}

*/

static void ldb_close(BlockDriverState *bs)
{
    LDBState *s = bs->opaque;

    LOG("closed connection \n");
    redisFree(s->data.context);
    redisFree(s->meta.context);
}

static int64_t ldb_getlength(BlockDriverState *bs)
{
    LDBState *s = bs->opaque;
    (void)s;
    int64_t ret = 1;

    return  ret << 34;
}

/*
static void ldb_detach_aio_context(BlockDriverState *bs)
{
    LDBState *s = bs->opaque;

    ldb_client_session_detach_aio_context(&s->client);
}

static void ldb_attach_aio_context(BlockDriverState *bs,
                                   AioContext *new_context)
{
    LDBState *s = bs->opaque;

    ldb_client_session_attach_aio_context(&s->client, new_context);
}
*/

static void ldb_refresh_filename(BlockDriverState *bs)
{
    LDBState *s = bs->opaque;
    (void) s;

}

static BlockDriver bdrv_ldb = {
    .format_name                = "ldb",
    .protocol_name              = "ldb",
    .instance_size              = sizeof(LDBState),
    //.bdrv_needs_filename        = true,
    .bdrv_parse_filename        = ldb_parse_filename,
    .bdrv_file_open             = ldb_open,
    .bdrv_read                  = ldb_read,
    .bdrv_write                 = ldb_write,
    .bdrv_close                 = ldb_close,
    //.bdrv_co_writev             = ldb_co_writev,
    //.bdrv_co_readv              = ldb_co_readv,
    //.bdrv_co_flush_to_os        = ldb_co_flush,
    //.bdrv_co_discard            = ldb_co_discard,
    .bdrv_getlength             = ldb_getlength,
    //.bdrv_detach_aio_context    = ldb_detach_aio_context,
    //.bdrv_attach_aio_context    = ldb_attach_aio_context,
    .bdrv_refresh_filename      = ldb_refresh_filename,
    //.create_opts                = ldb_create_opts,
};

// bdrv_probe, bdrv_reopen, bdrv_rebind, 
// bdrv_get_info, bdrv_check, 
// bdrv_get_allocated_file_size, 
// bdrv_truncate
// bdrv_flush_to_disk
// Does REDIS have async write/read


static void bdrv_ldb_init(void)
{
    bdrv_register(&bdrv_ldb);
}

block_init(bdrv_ldb_init);
