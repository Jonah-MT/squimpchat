#include "sqmp.h"
#include "msquic_wrapper.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

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
        return NULL;  /* EINTR */

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

    session->auth_stream       = stream;
    session->auth_username_len = auth->username_len;
    memcpy(session->auth_username,      auth->username,      auth->username_len);
    memcpy(session->auth_password_hash, auth->password_hash, SQMP_PASSWORD_HASH_LEN);

    auth_queue_enqueue(session);
}

void sqmp_process_auth_resp(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream;
    sqmp_msg_auth_resp_t *resp = (sqmp_msg_auth_resp_t *)pkt->msg;
    if (resp->status == SQMP_AUTH_STATUS_OK) {
        session->state = SQMP_SESSION_STATE_CONN_ESTABLISHED;
        printf("Authentication successful (session %u)\n", resp->session_id);
    } else {
        printf("Authentication failed (status 0x%02x)\n", resp->status);
    }
    fflush(stdout);
}
