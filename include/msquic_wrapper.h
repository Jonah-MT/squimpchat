#pragma once

#include "msquic.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <semaphore.h>

typedef struct sqmp_quic_ctx_s sqmp_quic_ctx_t;
typedef struct sqmp_conn_s sqmp_conn_t;
typedef struct sqmp_stream_s sqmp_stream_t;
typedef void (*sqmp_on_connected_cb)(sqmp_conn_t *conn);
typedef void (*sqmp_on_disconnected_cb)(sqmp_conn_t *conn);
typedef void (*sqmp_on_stream_open_cb)(sqmp_conn_t *conn, sqmp_stream_t *stream);
typedef void (*sqmp_on_stream_recv_cb)(sqmp_stream_t *stream, const uint8_t *data, size_t len);
typedef void (*sqmp_on_stream_peer_send_done_cb)(sqmp_stream_t *stream);
typedef void (*sqmp_on_stream_closed_cb)(sqmp_stream_t *stream);

typedef struct {
    const char *app_name;
    uint64_t    idle_timeout_ms;
    sqmp_on_connected_cb              on_connected;
    sqmp_on_disconnected_cb           on_disconnected;
    sqmp_on_stream_open_cb            on_stream_open;
    sqmp_on_stream_recv_cb            on_stream_recv;
    sqmp_on_stream_peer_send_done_cb  on_stream_peer_send_done;
    sqmp_on_stream_closed_cb          on_stream_closed;
} sqmp_quic_config_t;

typedef struct sqmp_quic_ctx_s {
    const QUIC_API_TABLE *msquic;
    HQUIC                 reg;
    HQUIC                 config;
    HQUIC                 listener;
    sqmp_quic_config_t    cfg;
} sqmp_quic_ctx_t;

typedef struct sqmp_conn_s {
    HQUIC             handle;
    sqmp_quic_ctx_t  *ctx;
    sem_t             connect_sem;
    sem_t             closed_sem;
    int               connected;
    int               is_server;
    void             *user_data;
} sqmp_conn_t;

typedef struct sqmp_stream_s {
    HQUIC          handle;
    sqmp_conn_t   *conn;
    void          *user_data;
} sqmp_stream_t;

sqmp_quic_ctx_t *sqmp_quic_init(const sqmp_quic_config_t *cfg);
void sqmp_quic_destroy(sqmp_quic_ctx_t *ctx);
int sqmp_quic_listen(sqmp_quic_ctx_t *ctx, const char *alpn, uint16_t port, const char *cert_file, const char *key_file);
sqmp_conn_t *sqmp_quic_connect(sqmp_quic_ctx_t *ctx, const char *alpn, const char *host, uint16_t port);
void sqmp_quic_disconnect(sqmp_conn_t *conn);
sqmp_stream_t *sqmp_stream_open(sqmp_conn_t *conn);
int sqmp_stream_send(sqmp_stream_t *stream, const uint8_t *data, size_t len);
void sqmp_stream_close(sqmp_stream_t *stream);
void sqmp_stream_send_done(sqmp_stream_t *stream);
void  sqmp_conn_set_user_data  (sqmp_conn_t   *conn,   void *data);
void *sqmp_conn_get_user_data  (sqmp_conn_t   *conn);
void  sqmp_stream_set_user_data(sqmp_stream_t *stream, void *data);
void *sqmp_stream_get_user_data(sqmp_stream_t *stream);
