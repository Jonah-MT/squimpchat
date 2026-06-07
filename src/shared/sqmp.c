#include "sqmp.h"
#include "msquic_wrapper.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

void sqmp_process_hello(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)pkt;
    uint32_t new_session_id;

    sqmp_pkt_t ack_pkt = {0};
    ack_pkt.msg_type = SQMP_MSG_TYPE_HELLO_ACK;

    new_session_id = atomic_fetch_add(&g_next_session_id, 1);
    ack_pkt.session_id = new_session_id;
    session->session_id = new_session_id;

    if (session->state == SQMP_SESSION_STATE_HELLO) {
        sqmp_stream_send(stream, (uint8_t *)&ack_pkt, sizeof(sqmp_pkt_t));
        session->state = SQMP_SESSION_STATE_AUTH;
    } else {
        fprintf(stderr, "Hello received when sqmp state is %d\n", session->state);
    }
}

void sqmp_process_hello_ack(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream;
    if (session->state != SQMP_SESSION_STATE_HELLO) {
        fprintf(stderr, "Hello ack received in unexpected state %d\n", session->state);
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
            printf("Authentication successful (session %u)\n", resp->session_id);
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


void sqmp_process_chat_deliver(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream;
    sqmp_msg_chat_deliver_t *msg = (sqmp_msg_chat_deliver_t *)pkt->msg;
    if (session->state == SQMP_SESSION_STATE_CONN_ESTABLISHED) {
        printf("[from: ");
        fflush(stdout);
        write(STDOUT_FILENO, msg->sender, msg->sender_len);
        printf("] ");
        fflush(stdout);
        write(STDOUT_FILENO, msg->ciphertext, msg->ciphertext_len);
        printf("\n");
    } else {
        fprintf(stderr, "CHAT_DELIVER in unexpected state %d\n", session->state);
    }
    fflush(stdout);
}

void sqmp_process_chat_send(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream;
    sqmp_msg_chat_send_t *msg = (sqmp_msg_chat_send_t *)pkt->msg;

    if (session->state != SQMP_SESSION_STATE_CONN_ESTABLISHED) {
        fprintf(stderr, "CHAT_SEND in unexpected state %d\n", session->state);
        return;
    }

    sqmp_stream_t *dst = sqmp_registry_find(msg->recipient, msg->recipient_len);
    if (!dst) return;

    size_t      pktlen = sizeof(sqmp_pkt_t) + sizeof(sqmp_msg_chat_deliver_t) + msg->ciphertext_len;
    sqmp_pkt_t *out    = malloc(pktlen);
    if (!out) return;
    memset(out, 0, pktlen);

    sqmp_msg_chat_deliver_t *deliver = (sqmp_msg_chat_deliver_t *)out->msg;

    out->version    = 1;
    out->msg_type   = SQMP_MSG_TYPE_CHAT_DELIVER;
    out->session_id = pkt->session_id;

    deliver->sender_len  = session->username_len;
    memcpy(deliver->sender, session->username, session->username_len);
    deliver->ciphertext_len = msg->ciphertext_len;
    memcpy(deliver->ciphertext, msg->ciphertext, msg->ciphertext_len);

    sqmp_stream_send(dst, (uint8_t *)out, pktlen);
    free(out);
}
