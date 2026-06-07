#include "msquic_wrapper.h"
#include "msquic.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>

typedef struct {
    QUIC_BUFFER qbuf;
    uint8_t     data[];
} send_buf_t;

static QUIC_STATUS QUIC_API
stream_cb(HQUIC handle, void *ctx_ptr, QUIC_STREAM_EVENT *ev)
{
    sqmp_stream_t            *stream = (sqmp_stream_t *)ctx_ptr;
    const sqmp_quic_config_t *cfg    = &stream->conn->ctx->cfg;
    const QUIC_API_TABLE     *ms     = stream->conn->ctx->msquic;

    switch (ev->Type) {

    case QUIC_STREAM_EVENT_RECEIVE: {
        uint64_t total = ev->RECEIVE.TotalBufferLength;
        uint8_t *flat  = malloc((size_t)total + 1);
        if (flat) {
            size_t off = 0;
            for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; i++) {
                memcpy(flat + off,
                       ev->RECEIVE.Buffers[i].Buffer,
                       ev->RECEIVE.Buffers[i].Length);
                off += ev->RECEIVE.Buffers[i].Length;
            }
            flat[total] = '\0';
            if (cfg->on_stream_recv)
                cfg->on_stream_recv(stream, flat, (size_t)total);
            free(flat);
        }
        break;
    }

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        if (cfg->on_stream_peer_send_done)
            cfg->on_stream_peer_send_done(stream);
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        free(ev->SEND_COMPLETE.ClientContext);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        if (cfg->on_stream_closed)
            cfg->on_stream_closed(stream);
        if (!ev->SHUTDOWN_COMPLETE.AppCloseInProgress)
            ms->StreamClose(handle);
        free(stream);
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
    case QUIC_STREAM_EVENT_START_COMPLETE:
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API
conn_cb(HQUIC handle, void *ctx_ptr, QUIC_CONNECTION_EVENT *ev)
{
    (void)handle;
    sqmp_conn_t              *conn = (sqmp_conn_t *)ctx_ptr;
    const sqmp_quic_config_t *cfg  = &conn->ctx->cfg;
    const QUIC_API_TABLE     *ms   = conn->ctx->msquic;

    switch (ev->Type) {

    case QUIC_CONNECTION_EVENT_CONNECTED:
        conn->connected = 1;
        if (cfg->on_connected)
            cfg->on_connected(conn);
        sem_post(&conn->connect_sem);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        fprintf(stderr, "[quic] transport shutdown: 0x%x\n",
                ev->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        if (!conn->connected)
            sem_post(&conn->connect_sem);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (cfg->on_disconnected)
            cfg->on_disconnected(conn);

        if (conn->is_server) {
            ms->ConnectionClose(conn->handle);
            sem_destroy(&conn->connect_sem);
            sem_destroy(&conn->closed_sem);
            free(conn);
        } else {
            sem_post(&conn->closed_sem);
        }
        break;

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        sqmp_stream_t *stream = calloc(1, sizeof(*stream));
        if (!stream) {
            ms->ConnectionClose(ev->PEER_STREAM_STARTED.Stream);
            break;
        }
        stream->handle = ev->PEER_STREAM_STARTED.Stream;
        stream->conn   = conn;
        ms->SetCallbackHandler(stream->handle, (void *)stream_cb, stream);
        if (cfg->on_stream_open)
            cfg->on_stream_open(conn, stream);
        break;
    }

    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API
listener_cb(HQUIC listener, void *ctx_ptr, QUIC_LISTENER_EVENT *ev)
{
    (void)listener;
    sqmp_quic_ctx_t *ctx = (sqmp_quic_ctx_t *)ctx_ptr;

    if (ev->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION)
        return QUIC_STATUS_SUCCESS;

    sqmp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn)
        return QUIC_STATUS_OUT_OF_MEMORY;

    conn->handle    = ev->NEW_CONNECTION.Connection;
    conn->ctx       = ctx;
    conn->is_server = 1;
    sem_init(&conn->connect_sem, 0, 0);
    sem_init(&conn->closed_sem,  0, 0);

    ctx->msquic->SetCallbackHandler(conn->handle, (void *)conn_cb, conn);

    if (QUIC_FAILED(ctx->msquic->ConnectionSetConfiguration(
            conn->handle, ctx->config))) {
        ctx->msquic->ConnectionClose(conn->handle);
        sem_destroy(&conn->connect_sem);
        sem_destroy(&conn->closed_sem);
        free(conn);
        return QUIC_STATUS_INTERNAL_ERROR;
    }
    return QUIC_STATUS_SUCCESS;
}

sqmp_quic_ctx_t *sqmp_quic_init(const sqmp_quic_config_t *cfg)
{
    sqmp_quic_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->cfg = *cfg;

    QUIC_STATUS s;
    if (QUIC_FAILED(s = MsQuicOpenVersion(QUIC_API_VERSION_2,
                                           (const void **)&ctx->msquic))) {
        fprintf(stderr, "[quic] MsQuicOpenVersion failed: 0x%x\n", s);
        free(ctx);
        return NULL;
    }

    const QUIC_REGISTRATION_CONFIG reg_cfg = {
        cfg->app_name ? cfg->app_name : "sqmp",
        QUIC_EXECUTION_PROFILE_LOW_LATENCY
    };
    if (QUIC_FAILED(s = ctx->msquic->RegistrationOpen(&reg_cfg, &ctx->reg))) {
        fprintf(stderr, "[quic] RegistrationOpen failed: 0x%x\n", s);
        MsQuicClose(ctx->msquic);
        free(ctx);
        return NULL;
    }
    return ctx;
}

void sqmp_quic_destroy(sqmp_quic_ctx_t *ctx)
{
    if (!ctx) return;
    if (ctx->listener) ctx->msquic->ListenerClose(ctx->listener);
    if (ctx->config)   ctx->msquic->ConfigurationClose(ctx->config);
    if (ctx->reg)      ctx->msquic->RegistrationClose(ctx->reg);
    MsQuicClose(ctx->msquic);
    free(ctx);
}

int sqmp_quic_listen(sqmp_quic_ctx_t *ctx,
                     const char *alpn, uint16_t port,
                     const char *cert_file, const char *key_file)
{
    QUIC_BUFFER alpn_buf = { (uint32_t)strlen(alpn), (uint8_t *)alpn };

    QUIC_SETTINGS settings = {0};
    settings.IdleTimeoutMs             = ctx->cfg.idle_timeout_ms
                                         ? ctx->cfg.idle_timeout_ms : 30000;
    settings.IsSet.IdleTimeoutMs       = TRUE;
    settings.PeerBidiStreamCount       = 16;
    settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_STATUS s;
    if (QUIC_FAILED(s = ctx->msquic->ConfigurationOpen(
            ctx->reg, &alpn_buf, 1,
            &settings, sizeof(settings), NULL, &ctx->config))) {
        fprintf(stderr, "[quic] ConfigurationOpen failed: 0x%x\n", s);
        return -1;
    }

    QUIC_CERTIFICATE_FILE cert = { key_file, cert_file };
    QUIC_CREDENTIAL_CONFIG cred = {0};
    cred.Type            = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cred.Flags           = QUIC_CREDENTIAL_FLAG_NONE;
    cred.CertificateFile = &cert;

    if (QUIC_FAILED(s = ctx->msquic->ConfigurationLoadCredential(
            ctx->config, &cred))) {
        fprintf(stderr, "[quic] ConfigurationLoadCredential failed: 0x%x\n", s);
        return -1;
    }

    if (QUIC_FAILED(s = ctx->msquic->ListenerOpen(
            ctx->reg, listener_cb, ctx, &ctx->listener))) {
        fprintf(stderr, "[quic] ListenerOpen failed: 0x%x\n", s);
        return -1;
    }

    QUIC_ADDR addr = {0};
    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&addr, port);

    if (QUIC_FAILED(s = ctx->msquic->ListenerStart(
            ctx->listener, &alpn_buf, 1, &addr))) {
        fprintf(stderr, "[quic] ListenerStart failed: 0x%x\n", s);
        return -1;
    }
    return 0;
}

sqmp_conn_t *sqmp_quic_connect(sqmp_quic_ctx_t *ctx,
                                const char *alpn,
                                const char *host, uint16_t port)
{
    QUIC_BUFFER alpn_buf = { (uint32_t)strlen(alpn), (uint8_t *)alpn };

    QUIC_SETTINGS settings = {0};
    uint64_t idle_ms = ctx->cfg.idle_timeout_ms ? ctx->cfg.idle_timeout_ms : 30000;
    settings.IdleTimeoutMs              = idle_ms;
    settings.IsSet.IdleTimeoutMs        = TRUE;
    settings.KeepAliveIntervalMs        = (uint32_t)(idle_ms / 2);
    settings.IsSet.KeepAliveIntervalMs  = TRUE;
    settings.PeerBidiStreamCount        = 16;
    settings.IsSet.PeerBidiStreamCount  = TRUE;

    QUIC_STATUS s;
    if (QUIC_FAILED(s = ctx->msquic->ConfigurationOpen(
            ctx->reg, &alpn_buf, 1,
            &settings, sizeof(settings), NULL, &ctx->config))) {
        fprintf(stderr, "[quic] ConfigurationOpen failed: 0x%x\n", s);
        return NULL;
    }

    QUIC_CREDENTIAL_CONFIG cred = {0};
    cred.Type  = QUIC_CREDENTIAL_TYPE_NONE;
    cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT
               | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    if (QUIC_FAILED(s = ctx->msquic->ConfigurationLoadCredential(
            ctx->config, &cred))) {
        fprintf(stderr, "[quic] ConfigurationLoadCredential failed: 0x%x\n", s);
        return NULL;
    }

    sqmp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    conn->ctx       = ctx;
    conn->is_server = 0;
    sem_init(&conn->connect_sem, 0, 0);
    sem_init(&conn->closed_sem,  0, 0);

    if (QUIC_FAILED(s = ctx->msquic->ConnectionOpen(
            ctx->reg, conn_cb, conn, &conn->handle))) {
        fprintf(stderr, "[quic] ConnectionOpen failed: 0x%x\n", s);
        goto fail;
    }

    if (QUIC_FAILED(s = ctx->msquic->ConnectionStart(
            conn->handle, ctx->config,
            QUIC_ADDRESS_FAMILY_INET, host, port))) {
        fprintf(stderr, "[quic] ConnectionStart failed: 0x%x\n", s);
        ctx->msquic->ConnectionClose(conn->handle);
        goto fail;
    }

    while (sem_wait(&conn->connect_sem) == -1 && errno == EINTR)
        ;
    if (!conn->connected) {
        return NULL;
    }
    return conn;

fail:
    sem_destroy(&conn->connect_sem);
    sem_destroy(&conn->closed_sem);
    free(conn);
    return NULL;
}

void sqmp_quic_disconnect(sqmp_conn_t *conn)
{
    if (!conn) return;
    conn->ctx->msquic->ConnectionShutdown(
        conn->handle, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    while (sem_wait(&conn->closed_sem) == -1 && errno == EINTR)
        ;
    conn->ctx->msquic->ConnectionClose(conn->handle);
    sem_destroy(&conn->connect_sem);
    sem_destroy(&conn->closed_sem);
    free(conn);
}

sqmp_stream_t *sqmp_stream_open(sqmp_conn_t *conn)
{
    sqmp_stream_t *stream = calloc(1, sizeof(*stream));
    if (!stream) return NULL;

    stream->conn = conn;

    QUIC_STATUS s;
    if (QUIC_FAILED(s = conn->ctx->msquic->StreamOpen(
            conn->handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            stream_cb, stream,
            &stream->handle))) {
        fprintf(stderr, "[quic] StreamOpen failed: 0x%x\n", s);
        free(stream);
        return NULL;
    }

    if (QUIC_FAILED(s = conn->ctx->msquic->StreamStart(
            stream->handle,
            QUIC_STREAM_START_FLAG_IMMEDIATE))) {
        fprintf(stderr, "[quic] StreamStart failed: 0x%x\n", s);
        conn->ctx->msquic->StreamClose(stream->handle);
        free(stream);
        return NULL;
    }
    return stream;
}

int sqmp_stream_send(sqmp_stream_t *stream, const uint8_t *data, size_t len)
{
    send_buf_t *sb = malloc(sizeof(send_buf_t) + len);
    if (!sb) return -1;

    memcpy(sb->data, data, len);
    sb->qbuf.Buffer = sb->data;
    sb->qbuf.Length = (uint32_t)len;

    QUIC_STATUS s = stream->conn->ctx->msquic->StreamSend(
        stream->handle, &sb->qbuf, 1, QUIC_SEND_FLAG_NONE, sb);
    if (QUIC_FAILED(s)) {
        free(sb);
        return -1;
    }
    return 0;
}

void sqmp_stream_send_done(sqmp_stream_t *stream)
{
    stream->conn->ctx->msquic->StreamShutdown(
        stream->handle, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
}

void sqmp_stream_close(sqmp_stream_t *stream)
{
    stream->conn->ctx->msquic->StreamShutdown(
        stream->handle, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
    stream->conn->ctx->msquic->StreamClose(stream->handle);
}

void  sqmp_conn_set_user_data  (sqmp_conn_t   *c, void *d) { c->user_data = d; }
void *sqmp_conn_get_user_data  (sqmp_conn_t   *c)          { return c->user_data; }
void  sqmp_stream_set_user_data(sqmp_stream_t *s, void *d) { s->user_data = d; }
void *sqmp_stream_get_user_data(sqmp_stream_t *s)          { return s->user_data; }
