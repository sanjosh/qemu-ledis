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

typedef struct LDBState {
    redisContext* metaContext;
    redisContext* dataContext; 
    int64_t zeroReads;
} LDBState;


/*
static int ldb_parse_uri(const char *filename, QDict *options)
{
    URI *uri;
    QueryParams *qp = NULL;
    int ret = 0;

    uri = uri_parse(filename);
    if (!uri) {
        return -EINVAL;
    }

    // transport 
    if (!strcmp(uri->scheme, "ldb")) {
        ret = -EINVAL;
        goto out;
    }

    qp = query_params_parse(uri->query);
    if (qp->n > 1) {
        ret = -EINVAL;
        goto out;
    }

    {
        QString *host;
        // nbd://host[:port]/export 
        if (!uri->server) {
            ret = -EINVAL;
            goto out;
        }

        host = qstring_from_str(uri->server);

        qdict_put(options, "host", host);

        if (uri->port) {
            char* port_str = g_strdup_printf("%d", uri->port);
            qdict_put(options, "port", qstring_from_str(port_str));
            g_free(port_str);
        }
    }

out:
    if (qp) {
        query_params_free(qp);
    }
    uri_free(uri);
    return ret;
}
*/

static void ldb_parse_filename(const char *filename, QDict *options,
                               Error **errp)
{
/*
    char *file;
    const char *host_spec;

    if (strstr(filename, "://")) {
        int ret = ldb_parse_uri(filename, options);
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

    // are we a UNIX or TCP socket? 
    {
        InetSocketAddress *addr = NULL;

        addr = inet_parse(host_spec, errp);
        if (!addr) {
            goto out;
        }

        qdict_put(options, "host", qstring_from_str(addr->host));
        qdict_put(options, "port", qstring_from_str(addr->port));
        qapi_free_InetSocketAddress(addr);
    }

out:
    g_free(file);
*/
}

static int ldb_establish_connection(BlockDriverState *bs, Error **errp)
{
    LDBState *s = bs->opaque;

    s->zeroReads = 0;

    int dataService = DATASERVICE;
    int dataPort = DATAPORT;

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds

    s->dataContext = redisConnectTIPCWithTimeout(dataService, dataPort, timeout);

    if (s->dataContext == NULL || s->dataContext->err) 
    {
        if (s->dataContext) 
        {
            error_setg_errno(errp, -ENOTCONN, "Connection error: %s", s->dataContext->errstr);
            redisFree(s->dataContext);
        } 
        else 
        {
            error_setg_errno(errp, -ENOTCONN, "Connection error: can't allocate redis context\n");
        }
        return -ENOTCONN;
    }

    return 0;
}

static int ldb_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp)
{
    LDBState *s = bs->opaque;
    (void) s;

    /* Pop the config into our state object. Exit if invalid. */
    //ldb_config(s, options, &export, &local_err);
    //if (local_err) {
        //error_propagate(errp, local_err);
        //return -EINVAL;
    //}

    /* establish TCP connection, return error if it fails
     * TODO: Configurable retry-until-timeout behaviour.
     */
    int ret = ldb_establish_connection(bs, errp);

    /* LDB handshake */
    //result = ldb_client_session_init(&s->client, bs, sock, export);
    //g_free(export);
    LOG("opened connection with ret=%d\n", ret);
    return ret;
}

//#define LDB_BLKSIZE (4096)
//#define NUMSECTORS (LDB_BLKSIZE/512)

#define LDB_BLKSIZE (512)
#define NUMSECTORS (LDB_BLKSIZE/512)

static int ldb_read(BlockDriverState *bs, int64_t sector_num,
    uint8_t *buf, int nb_sectors)
{
    LDBState *s = bs->opaque;
    int result = 0;

    char query[100];
    uint8_t* curBuf = buf;
    int64_t curSector = sector_num;
    int i = 0;

    for (i = 0; i < nb_sectors/NUMSECTORS; i++)
    {
        sprintf(query, "GET %lu", curSector);

        redisReply* reply = redisCommand(s->dataContext, query);

        if (reply->type == REDIS_REPLY_ERROR)
        {
            error_report("Read error: %s %d %s", reply->str, s->dataContext->err, s->dataContext->errstr);
            result = -EIO;
            break;
        }
        else
        {
            if (reply->len == 0)
            {
                s->zeroReads ++;
                bzero(curBuf, LDB_BLKSIZE);
                if (s->zeroReads && (s->zeroReads % 100 == 0))
                {
                    LOG("num zero reads=%lu\n", s->zeroReads);
                }
            }
            else
            {
                memcpy(curBuf, reply->str, reply->len);
            }
        }

        freeReplyObject(reply);

        curBuf += LDB_BLKSIZE;
        curSector += NUMSECTORS;
    }

    return result;
}

static int ldb_write(BlockDriverState *bs, int64_t sector_num,
    const uint8_t *buf, int nb_sectors)
{
    LDBState *s = bs->opaque;

    char query[100];

    const uint8_t* curBuf = buf;
    int64_t curSector = sector_num;
    int i = 0;

    for (i = 0; i < nb_sectors/NUMSECTORS; i++)
    {
        sprintf(query, "%lu", curSector);

        redisReply* reply = redisCommand(s->dataContext, "SET %b %b", query, strlen(query), curBuf, LDB_BLKSIZE);
        freeReplyObject(reply);

        curBuf += LDB_BLKSIZE;
        curSector += NUMSECTORS;
    }
    return 0;
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
    redisFree(s->dataContext);
    //redisFree(s->metaContext);
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
