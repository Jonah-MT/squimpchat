#include "server.h"
#include "sqmp.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include "debug.h"

static volatile sig_atomic_t g_stop;

/*
 * sig_handler
 * Sets the stop flag on SIGINT/SIGTERM.
 *
 * in:  sig - signal number (unused)
 */
static void sig_handler(int sig) { (void)sig; g_stop = 1; }

/*
 * verify_credentials
 * Checks a username and password hash against users.txt.
 *
 * in:  username      - null-terminated username string
 *      password_hash - SHA-256 hash of the password (32 bytes)
 * out: 1 if credentials match, 0 otherwise
 */
static int verify_credentials(const char *username, const uint8_t *password_hash)
{
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) {
        fprintf(stderr, "cannot open %s: %s\n", USERS_FILE, strerror(errno));
        return 0;
    }

    char line[256];
    int  result = 0;
    while (fgets(line, sizeof(line), f)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';

        if (strcmp(username, line) != 0) continue;

        char  *hex  = colon + 1;
        size_t hlen = strlen(hex);
        while (hlen > 0 && (hex[hlen - 1] == '\n' || hex[hlen - 1] == '\r'))
            hex[--hlen] = '\0';

        if (hlen != SQMP_PASSWORD_HASH_LEN * 2) break;

        uint8_t stored[SQMP_PASSWORD_HASH_LEN];
        for (int i = 0; i < SQMP_PASSWORD_HASH_LEN; i++) {
            unsigned int b;
            sscanf(hex + i * 2, "%02x", &b);
            stored[i] = (uint8_t)b;
        }
        result = memcmp(password_hash, stored, SQMP_PASSWORD_HASH_LEN) == 0;
        break;
    }
    fclose(f);
    return result;
}

/*
 * send_auth_resp
 * Sends an AUTH_RESP packet with OK or INVALID status.
 *
 * in:  stream  - stream to send on
 *      session - session (used for session_id and username)
 *      ok      - 1 for success, 0 for failure
 */
static void send_auth_resp(sqmp_stream_t *stream, sqmp_session_t *session, int ok)
{
    uint8_t buf[sizeof(sqmp_pkt_t) + sizeof(sqmp_msg_auth_resp_t)];
    memset(buf, 0, sizeof(buf));
    sqmp_pkt_t           *pkt  = (sqmp_pkt_t *)buf;
    sqmp_msg_auth_resp_t *resp = (sqmp_msg_auth_resp_t *)pkt->msg;

    pkt->version    = 1;
    pkt->msg_type   = SQMP_MSG_TYPE_AUTH_RESP;
    pkt->session_id = session->session_id;

    resp->status     = ok ? SQMP_AUTH_STATUS_OK : SQMP_AUTH_STATUS_INVALID;
    resp->session_id = session->session_id;

    sqmp_stream_send(stream, buf, sizeof(buf));
    dbg_printf("[sent] MSG_AUTH_RESP (user='%.*s' status=%s)\n",
               (int)session->auth_username_len, session->auth_username,
               ok ? "ok" : "fail");
}

/*
 * sqmp_process_bye
 * Handler for MSG_BYE. Removes the user from the registry
 * and prints a disconnect notice.
 *
 * in:  stream, session, pkt - standard handler args
 */
void sqmp_process_bye(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)stream; (void)pkt;
    if (session->state == SQMP_SESSION_STATE_CONN_ESTABLISHED) {
        sqmp_registry_remove(session->username, session->username_len);
        session->state = SQMP_SESSION_STATE_CLOSING;
        printf("'%.*s' disconnected\n", (int)session->username_len, session->username);
        fflush(stdout);
    }
}

/*
 * on_stream_closed
 * Clears the session's auth_stream pointer when a stream closes.
 *
 * in:  stream - the stream that closed
 */
static void on_stream_closed(sqmp_stream_t *stream)
{
    sqmp_session_t *session = sqmp_stream_get_user_data(stream);
    if (session) {
        atomic_store(&session->auth_stream, (sqmp_stream_t *)NULL);
    }
}

/*
 * on_connected
 * Allocates a fresh session for a newly connected client.
 *
 * in:  conn - the new connection
 */
static void on_connected(sqmp_conn_t *conn)
{
    sqmp_session_t *session = calloc(1, sizeof(*session));
    if (!session) {
        fprintf(stderr, "failed to allocate session\n");
        return;
    }
    session->state = SQMP_SESSION_STATE_HELLO;
    sem_init(&session->login_ready, 0, 0);
    sqmp_conn_set_user_data(conn, session);

    printf("Client connected\n");
    fflush(stdout);
}

/*
 * on_stream_open
 * Attaches the connection's session to a newly opened stream.
 *
 * in:  conn   - the connection
 *      stream - the newly opened stream
 */
static void on_stream_open(sqmp_conn_t *conn, sqmp_stream_t *stream)
{
    sqmp_stream_set_user_data(stream, sqmp_conn_get_user_data(conn));

    printf("Stream opened by client\n");
    fflush(stdout);
}

/*
 * on_stream_recv
 * Dispatches an incoming packet to the appropriate handler function.
 *
 * in:  stream - stream the data arrived on
 *      data   - raw packet bytes
 *      len    - number of bytes
 */
static void on_stream_recv(sqmp_stream_t *stream,
                            const uint8_t *data, size_t len)
{
    if (len < SQMP_PKT_FIXED_LEN) {
        fprintf(stderr, "packet too short (%zu bytes), ignoring\n", len);
        return;
    }
    sqmp_session_t *session = sqmp_stream_get_user_data(stream);
    sqmp_pkt_t     *pkt     = (sqmp_pkt_t *)data;

    sqmp_dbg_recv_pkt(pkt);
    switch (pkt->msg_type) {
        case SQMP_MSG_TYPE_HELLO:
            sqmp_process_hello(stream, session, pkt);
            break;
        case SQMP_MSG_TYPE_AUTH_REQ:
            sqmp_process_auth_req(stream, session, pkt);
            break;
        case SQMP_MSG_TYPE_KEY_REQ:
            sqmp_process_key_req(stream, session, pkt);
            break;
        case SQMP_MSG_TYPE_CHAT_SEND:
            sqmp_process_chat_send(stream, session, pkt);
            break;
        case SQMP_MSG_TYPE_ERROR:
            sqmp_process_error(stream, session, pkt);
            break;
        case SQMP_MSG_TYPE_BYE:
            sqmp_process_bye(stream, session, pkt);
            break;
        default:
            fprintf(stderr, "unhandled msg_type 0x%02x\n", pkt->msg_type);
            break;
    }
}

/*
 * on_disconnected
 * Session cleanup when a client disconnects
 *
 * in:  conn - the connection that dropped
 */
static void on_disconnected(sqmp_conn_t *conn)
{
    sqmp_session_t *session = sqmp_conn_get_user_data(conn);
    if (session) {
        if (atomic_load(&session->auth_queued)) {
            atomic_store(&session->conn_closed, (uint8_t)1);
            printf("Client disconnected (auth pending)\n");
            fflush(stdout);
            return;
        }
        if (session->state == SQMP_SESSION_STATE_CONN_ESTABLISHED)
            sqmp_registry_remove(session->username, session->username_len);
        sem_destroy(&session->login_ready);
        free(session);
    }

    printf("Client disconnected\n");
    fflush(stdout);
}

/* --------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------*/

int main(void)
{
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    sqmp_quic_config_t cfg = {
        .app_name        = "squimpchat-server",
        .idle_timeout_ms = 30000,
        .on_connected    = on_connected,
        .on_disconnected = on_disconnected,
        .on_stream_open  = on_stream_open,
        .on_stream_recv  = on_stream_recv,
        .on_stream_closed = on_stream_closed,
    };

    sqmp_quic_ctx_t *ctx = sqmp_quic_init(&cfg);
    if (!ctx) return 1;

    struct sigaction sa = {0};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

    sqmp_auth_queue_init();

    if (sqmp_quic_listen(ctx, SERVER_ALPN, SERVER_PORT,
                         SERVER_CERT, SERVER_KEY) != 0) {
        sqmp_quic_destroy(ctx);
        return 1;
    }

    printf("Listening on port %d (Ctrl+C to stop)...\n", SERVER_PORT);
    fflush(stdout);

    sqmp_session_t *pending;
    while (!g_stop && (pending = sqmp_auth_queue_dequeue()) != NULL) {
        atomic_store(&pending->auth_queued, (uint8_t)0);

        if (atomic_load(&pending->conn_closed)) {
            sem_destroy(&pending->login_ready);
            free(pending);
            continue;
        }

        char username[SQMP_USERNAME_MAX_LEN + 1] = {0};
        memcpy(username, pending->auth_username, pending->auth_username_len);

        int ok = verify_credentials(username, pending->auth_password_hash);
        if (ok) {
            if (sqmp_registry_add(pending->auth_username, pending->auth_username_len,
                                  atomic_load(&pending->auth_stream),
                                  pending->auth_pubkey) == 0) {
                pending->username_len = pending->auth_username_len;
                memcpy(pending->username, pending->auth_username, pending->auth_username_len);
                pending->state = SQMP_SESSION_STATE_CONN_ESTABLISHED;
                printf("Auth OK for '%s'\n", username);
            } else {
                ok = 0;
                printf("Auth FAILED for '%s' (already logged in)\n", username);
            }
        } else {
            printf("Auth FAILED for '%s'\n", username);
        }
        fflush(stdout);

        sqmp_stream_t *auth_stream = atomic_load(&pending->auth_stream);
        if (auth_stream)
            send_auth_resp(auth_stream, pending, ok);
    }

    if (g_stop) {
        printf("\nInterrupted, shutting down...\n");
        fflush(stdout);
        sqmp_registry_send_bye_all();
        sqmp_registry_shutdown_connections();
    }

    sqmp_quic_destroy(ctx);
    return 0;
}
