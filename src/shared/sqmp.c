#include "sqmp.h"
#include "msquic_wrapper.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "debug.h"

static _Atomic uint32_t g_next_session_id = 1;

static pthread_mutex_t g_auth_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static sem_t           g_auth_queue_sem;
static sqmp_session_t *g_auth_queue_head  = NULL;
static sqmp_session_t *g_auth_queue_tail  = NULL;

void sqmp_auth_queue_init(void)
{
    sem_init(&g_auth_queue_sem, 0, 0);
}

sqmp_session_t *sqmp_auth_queue_dequeue(void)
{
    if (sem_wait(&g_auth_queue_sem) != 0)
        return NULL;

    pthread_mutex_lock(&g_auth_queue_mutex);
    sqmp_session_t *s = g_auth_queue_head;
    if (s) {
        g_auth_queue_head = s->next;
        if (!g_auth_queue_head)
            g_auth_queue_tail = NULL;
        s->next = NULL;
    }
    pthread_mutex_unlock(&g_auth_queue_mutex);
    return s;
}

static void auth_queue_enqueue(sqmp_session_t *session)
{
    session->next = NULL;
    pthread_mutex_lock(&g_auth_queue_mutex);
    if (!g_auth_queue_tail) {
        g_auth_queue_head = g_auth_queue_tail = session;
    } else {
        g_auth_queue_tail->next = session;
        g_auth_queue_tail       = session;
    }
    pthread_mutex_unlock(&g_auth_queue_mutex);
    sem_post(&g_auth_queue_sem);
}

typedef struct {
    uint8_t        in_use;
    uint8_t        username_len;
    uint8_t        username[SQMP_USERNAME_MAX_LEN];
    uint8_t        public_key[32];
    sqmp_stream_t *stream;
} sqmp_registry_entry_t;

static pthread_mutex_t       g_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static sqmp_registry_entry_t g_registry[SQMP_REGISTRY_MAX];

int sqmp_registry_add(const uint8_t *uname, uint8_t ulen, sqmp_stream_t *stream, const uint8_t *pubkey)
{
    int slot = -1;
    pthread_mutex_lock(&g_registry_mutex);
    for (int i = 0; i < SQMP_REGISTRY_MAX; i++) {
        if (!g_registry[i].in_use) {
            if (slot < 0) slot = i;
            continue;
        }
        if (g_registry[i].username_len == ulen &&
            memcmp(g_registry[i].username, uname, ulen) == 0) {
            pthread_mutex_unlock(&g_registry_mutex);
            return -1;
        }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&g_registry_mutex);
        return -1;
    }
    g_registry[slot].in_use       = 1;
    g_registry[slot].username_len = ulen;
    memcpy(g_registry[slot].username, uname, ulen);
    g_registry[slot].stream       = stream;
    memcpy(g_registry[slot].public_key, pubkey, 32);
    pthread_mutex_unlock(&g_registry_mutex);
    return 0;
}

void sqmp_registry_remove(const uint8_t *uname, uint8_t ulen)
{
    pthread_mutex_lock(&g_registry_mutex);
    for (int i = 0; i < SQMP_REGISTRY_MAX; i++) {
        if (g_registry[i].in_use &&
            g_registry[i].username_len == ulen &&
            memcmp(g_registry[i].username, uname, ulen) == 0) {
            memset(&g_registry[i], 0, sizeof(g_registry[i]));
            break;
        }
    }
    pthread_mutex_unlock(&g_registry_mutex);
}

sqmp_stream_t *sqmp_registry_find(const uint8_t *uname, uint8_t ulen)
{
    sqmp_stream_t *stream = NULL;
    pthread_mutex_lock(&g_registry_mutex);
    for (int i = 0; i < SQMP_REGISTRY_MAX; i++) {
        if (g_registry[i].in_use &&
            g_registry[i].username_len == ulen &&
            memcmp(g_registry[i].username, uname, ulen) == 0) {
            stream = g_registry[i].stream;
            break;
        }
    }
    pthread_mutex_unlock(&g_registry_mutex);
    return stream;
}

int sqmp_registry_get_pubkey(const uint8_t *uname, uint8_t ulen, uint8_t pubkey_out[32])
{
    int found = -1;
    pthread_mutex_lock(&g_registry_mutex);
    for (int i = 0; i < SQMP_REGISTRY_MAX; i++) {
        if (g_registry[i].in_use &&
            g_registry[i].username_len == ulen &&
            memcmp(g_registry[i].username, uname, ulen) == 0) {
            memcpy(pubkey_out, g_registry[i].public_key, 32);
            found = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_registry_mutex);
    return found;
}

void sqmp_send_bye(sqmp_stream_t *stream, sqmp_session_t *session)
{
    sqmp_pkt_t pkt    = {0};
    pkt.version       = 1;
    pkt.msg_type      = SQMP_MSG_TYPE_BYE;
    pkt.session_id    = session ? session->session_id : 0;
    sqmp_stream_send(stream, (uint8_t *)&pkt, sizeof(pkt));
    dbg_printf("[sent] MSG_BYE (session=%u)\n", session ? session->session_id : 0);
}

__attribute__((weak))
void sqmp_process_bye(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream; (void)session; (void)pkt;
}

void sqmp_registry_send_bye_all(void)
{
    pthread_mutex_lock(&g_registry_mutex);
    for (int i = 0; i < SQMP_REGISTRY_MAX; i++) {
        if (g_registry[i].in_use && g_registry[i].stream) {
            sqmp_pkt_t pkt = {0};
            pkt.version    = 1;
            pkt.msg_type   = SQMP_MSG_TYPE_BYE;
            sqmp_stream_send(g_registry[i].stream, (uint8_t *)&pkt, sizeof(pkt));
        }
    }
    pthread_mutex_unlock(&g_registry_mutex);
}

void sqmp_registry_shutdown_connections(void)
{
    pthread_mutex_lock(&g_registry_mutex);
    for (int i = 0; i < SQMP_REGISTRY_MAX; i++) {
        if (g_registry[i].in_use && g_registry[i].stream) {
            sqmp_conn_t *conn = g_registry[i].stream->conn;
            conn->ctx->msquic->ConnectionShutdown(
                conn->handle, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
    }
    pthread_mutex_unlock(&g_registry_mutex);
}

void sqmp_process_hello(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    if (session->state != SQMP_SESSION_STATE_HELLO) {
        fprintf(stderr, "Hello received when sqmp state is %d\n", session->state);
        return;
    }

    sqmp_msg_hello_t *hello = (sqmp_msg_hello_t *)pkt->msg;
    int has_v1 = 0;
    for (int i = 0; i < hello->num_versions && i < 8; i++) {
        if (hello->versions[i] == 1) { has_v1 = 1; break; }
    }
    if (!has_v1) {
        fprintf(stderr, "Client does not support version 1\n");
        return;
    }

    uint8_t buf[sizeof(sqmp_pkt_t) + sizeof(sqmp_msg_hello_ack_t)];
    memset(buf, 0, sizeof(buf));
    sqmp_pkt_t           *ack_pkt = (sqmp_pkt_t *)buf;
    sqmp_msg_hello_ack_t *ack     = (sqmp_msg_hello_ack_t *)ack_pkt->msg;

    uint32_t new_session_id = atomic_fetch_add(&g_next_session_id, 1);
    ack_pkt->version          = 1;
    ack_pkt->msg_type         = SQMP_MSG_TYPE_HELLO_ACK;
    ack_pkt->session_id       = new_session_id;
    session->session_id       = new_session_id;
    ack->selected_version     = 1;
    ack->max_message_size     = 65535;

    sqmp_stream_send(stream, buf, sizeof(buf));
    dbg_printf("[sent] MSG_HELLO_ACK (session=%u)\n", new_session_id);
    session->state = SQMP_SESSION_STATE_AUTH;
}

void sqmp_process_hello_ack(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream;
    if (session->state != SQMP_SESSION_STATE_HELLO) {
        fprintf(stderr, "Hello ack received in unexpected state %d\n", session->state);
        return;
    }
    sqmp_msg_hello_ack_t *ack = (sqmp_msg_hello_ack_t *)pkt->msg;
    if (ack->selected_version != 1) {
        fprintf(stderr, "Server selected unsupported version %d\n", ack->selected_version);
        return;
    }
    session->session_id = pkt->session_id;
    session->state      = SQMP_SESSION_STATE_AUTH;
    sem_post(&session->login_ready);
}

void sqmp_process_auth_req(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    if (session->state != SQMP_SESSION_STATE_AUTH) {
        fprintf(stderr, "AUTH_REQ in unexpected state %d\n", session->state);
        return;
    }
    sqmp_msg_auth_req_t *auth = (sqmp_msg_auth_req_t *)pkt->msg;

    session->auth_username_len = auth->username_len;
    memcpy(session->auth_username,      auth->username,      auth->username_len);
    memcpy(session->auth_password_hash, auth->password_hash, SQMP_PASSWORD_HASH_LEN);
    if (auth->pubkey_len == 32)
        memcpy(session->auth_pubkey, auth->public_key, 32);
    atomic_store(&session->auth_stream, stream);
    atomic_store(&session->auth_queued, (uint8_t)1);
    auth_queue_enqueue(session);
}

void sqmp_process_auth_resp(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream;
    sqmp_msg_auth_resp_t *resp = (sqmp_msg_auth_resp_t *)pkt->msg;

    if (session->state == SQMP_SESSION_STATE_AUTH) {
        if (resp->status == SQMP_AUTH_STATUS_OK) {
            session->state   = SQMP_SESSION_STATE_CONN_ESTABLISHED;
            session->auth_ok = 1;
        } else {
            session->auth_ok = 0;
            printf("Authentication failed (status 0x%02x)\n", resp->status);
        }
    } else {
        fprintf(stderr, "AUTH_RESP in unexpected state %d\n", session->state);
    }
    fflush(stdout);
    sem_post(&session->auth_done);
}


__attribute__((weak))
void sqmp_process_chat_deliver(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream;
    (void)session;
    (void)pkt;
}

void sqmp_process_chat_send(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream;
    sqmp_msg_chat_send_t *msg = (sqmp_msg_chat_send_t *)pkt->msg;

    if (session->state != SQMP_SESSION_STATE_CONN_ESTABLISHED) {
        fprintf(stderr, "CHAT_SEND in unexpected state %d\n", session->state);
        return;
    }

    sqmp_stream_t *recipient = sqmp_registry_find(msg->recipient, msg->recipient_len);
    if (!recipient) return;

    size_t      pktlen = sizeof(sqmp_pkt_t) + sizeof(sqmp_msg_chat_deliver_t) + msg->ciphertext_len;
    sqmp_pkt_t *out    = malloc(pktlen);
    if (!out) return;
    memset(out, 0, pktlen);

    sqmp_msg_chat_deliver_t *deliver = (sqmp_msg_chat_deliver_t *)out->msg;

    out->version    = 1;
    out->msg_type   = SQMP_MSG_TYPE_CHAT_DELIVER;
    out->session_id = pkt->session_id;

    deliver->sender_len = session->username_len;
    memcpy(deliver->sender, session->username, session->username_len);
    deliver->enc_key_len = msg->enc_key_len;
    memcpy(deliver->encrypted_key, msg->encrypted_key, sizeof(deliver->encrypted_key));
    memcpy(deliver->nonce, msg->nonce, sizeof(deliver->nonce));
    deliver->ciphertext_len = msg->ciphertext_len;
    memcpy(deliver->ciphertext, msg->ciphertext, msg->ciphertext_len);

    sqmp_stream_send(recipient, (uint8_t *)out, pktlen);
    dbg_printf("[sent] MSG_CHAT_DELIVER (from='%.*s' to='%.*s' ciphertext_len=%u)\n",
               (int)session->username_len, session->username,
               (int)msg->recipient_len, msg->recipient,
               msg->ciphertext_len);
    free(out);
}


void sqmp_process_key_req(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    if (session->state != SQMP_SESSION_STATE_CONN_ESTABLISHED) {
        fprintf(stderr, "KEY_REQ in unexpected state %d\n", session->state);
        return;
    }
    sqmp_msg_key_req_t *req = (sqmp_msg_key_req_t *)pkt->msg;

    uint8_t pubkey[32];
    if (sqmp_registry_get_pubkey(req->username, req->username_len, pubkey) != 0)
        return;

    size_t   pktlen  = sizeof(sqmp_pkt_t) + sizeof(sqmp_msg_key_resp_t) + 32;
    uint8_t *buf     = malloc(pktlen);
    if (!buf) return;
    memset(buf, 0, pktlen);

    sqmp_pkt_t          *resp_pkt = (sqmp_pkt_t *)buf;
    sqmp_msg_key_resp_t *resp     = (sqmp_msg_key_resp_t *)resp_pkt->msg;

    resp_pkt->version    = 1;
    resp_pkt->msg_type   = SQMP_MSG_TYPE_KEY_RESP;
    resp_pkt->session_id = pkt->session_id;

    resp->username_len = req->username_len;
    memcpy(resp->username, req->username, req->username_len);
    resp->pubkey_len = 32;
    memcpy(resp->public_key, pubkey, 32);

    sqmp_stream_send(stream, buf, pktlen);
    dbg_printf("[sent] MSG_KEY_RESP (for='%.*s')\n", (int)req->username_len, req->username);
    free(buf);
}

void sqmp_process_key_resp(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream;
    sqmp_msg_key_resp_t *resp = (sqmp_msg_key_resp_t *)pkt->msg;
    if (resp->pubkey_len == 32)
        memcpy(session->key_fetch_result, resp->public_key, 32);
    else
        memset(session->key_fetch_result, 0, 32);
    sem_post(&session->key_fetch_sem);
}

void sqmp_dbg_recv_pkt(const sqmp_pkt_t *pkt)
{
#ifdef DEBUG
    switch (pkt->msg_type) {
    case SQMP_MSG_TYPE_HELLO: {
        sqmp_msg_hello_t *h = (sqmp_msg_hello_t *)pkt->msg;
        dbg_printf("[recv] MSG_HELLO (num_versions=%d)\n", (int)h->num_versions);
        break;
    }
    case SQMP_MSG_TYPE_HELLO_ACK: {
        sqmp_msg_hello_ack_t *h = (sqmp_msg_hello_ack_t *)pkt->msg;
        dbg_printf("[recv] MSG_HELLO_ACK (session=%u version=%u)\n",
                   pkt->session_id, (unsigned)h->selected_version);
        break;
    }
    case SQMP_MSG_TYPE_AUTH_REQ: {
        sqmp_msg_auth_req_t *a = (sqmp_msg_auth_req_t *)pkt->msg;
        dbg_printf("[recv] MSG_AUTH_REQ (user='%.*s')\n",
                   (int)a->username_len, a->username);
        break;
    }
    case SQMP_MSG_TYPE_AUTH_RESP: {
        sqmp_msg_auth_resp_t *a = (sqmp_msg_auth_resp_t *)pkt->msg;
        dbg_printf("[recv] MSG_AUTH_RESP (status=%s session=%u)\n",
                   a->status == SQMP_AUTH_STATUS_OK ? "ok" : "fail",
                   a->session_id);
        break;
    }
    case SQMP_MSG_TYPE_KEY_REQ: {
        sqmp_msg_key_req_t *k = (sqmp_msg_key_req_t *)pkt->msg;
        dbg_printf("[recv] MSG_KEY_REQ (for='%.*s')\n",
                   (int)k->username_len, k->username);
        break;
    }
    case SQMP_MSG_TYPE_KEY_RESP: {
        sqmp_msg_key_resp_t *k = (sqmp_msg_key_resp_t *)pkt->msg;
        dbg_printf("[recv] MSG_KEY_RESP (for='%.*s')\n",
                   (int)k->username_len, k->username);
        break;
    }
    case SQMP_MSG_TYPE_BYE:
        dbg_printf("[recv] MSG_BYE (session=%u)\n", pkt->session_id);
        break;
    case SQMP_MSG_TYPE_CHAT_SEND: {
        sqmp_msg_chat_send_t *c = (sqmp_msg_chat_send_t *)pkt->msg;
        dbg_printf("[recv] MSG_CHAT_SEND (to='%.*s' ciphertext_len=%u)\n",
                   (int)c->recipient_len, c->recipient, c->ciphertext_len);
        break;
    }
    case SQMP_MSG_TYPE_CHAT_DELIVER: {
        sqmp_msg_chat_deliver_t *c = (sqmp_msg_chat_deliver_t *)pkt->msg;
        dbg_printf("[recv] MSG_CHAT_DELIVER (from='%.*s' ciphertext_len=%u)\n",
                   (int)c->sender_len, c->sender, c->ciphertext_len);
        break;
    }
    default:
        dbg_printf("[recv] MSG_UNKNOWN (type=0x%02x session=%u)\n",
                   pkt->msg_type, pkt->session_id);
        break;
    }
#else
    (void)pkt;
#endif
}
