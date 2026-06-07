#include "client.h"
#include "sqmp.h"
#include <errno.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static volatile sig_atomic_t g_interrupted;

static void sig_handler(int sig)
{
    (void)sig;
    g_interrupted = 1;
}

static void on_connected(sqmp_conn_t *conn)
{
    (void)conn;
    printf("QUIC connection established\n");
    fflush(stdout);
}

static void on_stream_recv(sqmp_stream_t *stream,
                            const uint8_t *data, size_t len)
{
    if (len < SQMP_PKT_FIXED_LEN) {
        fprintf(stderr, "short packet (%zu bytes), ignoring\n", len);
        return;
    }
    sqmp_session_t *session = sqmp_stream_get_user_data(stream);
    sqmp_pkt_t     *pkt     = (sqmp_pkt_t *)data;

    switch (pkt->msg_type) {
    case SQMP_MSG_TYPE_HELLO_ACK:
        sqmp_process_hello_ack(stream, session, pkt);
        break;
    case SQMP_MSG_TYPE_AUTH_RESP:
        sqmp_process_auth_resp(stream, session, pkt);
        break;
    default:
        fprintf(stderr, "unhandled msg_type 0x%02x\n", pkt->msg_type);
        break;
    }
}

static void on_disconnected(sqmp_conn_t *conn)
{
    (void)conn;
    printf("Disconnected from server\n");
    fflush(stdout);
}

static int sqmp_login(sqmp_stream_t *stream, sqmp_session_t *session)
{
    char username[SQMP_USERNAME_MAX_LEN + 1] = {0};
    char password[256]                        = {0};

    printf("Username: ");
    fflush(stdout);
    if (!fgets(username, sizeof(username), stdin)) return -1;
    size_t ulen = strlen(username);
    if (ulen > 0 && username[ulen - 1] == '\n') username[--ulen] = '\0';
    if (ulen == 0 || ulen > SQMP_USERNAME_MAX_LEN) {
        fprintf(stderr, "invalid username length\n");
        return -1;
    }

    printf("Password: ");
    fflush(stdout);
    struct termios old_t, new_t;
    tcgetattr(STDIN_FILENO, &old_t);
    new_t         = old_t;
    new_t.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_t);
    char *rd = fgets(password, sizeof(password), stdin);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
    printf("\n");
    if (!rd) return -1;
    size_t pwlen = strlen(password);
    if (pwlen > 0 && password[pwlen - 1] == '\n') password[--pwlen] = '\0';

    uint8_t pw_hash[SQMP_PASSWORD_HASH_LEN];
    SHA256((const unsigned char *)password, pwlen, pw_hash);
    memset(password, 0, sizeof(password));

    uint8_t buf[sizeof(sqmp_pkt_t) + sizeof(sqmp_msg_auth_req_t)];
    memset(buf, 0, sizeof(buf));
    sqmp_pkt_t          *pkt  = (sqmp_pkt_t *)buf;
    sqmp_msg_auth_req_t *auth = (sqmp_msg_auth_req_t *)pkt->msg;

    pkt->version    = 1;
    pkt->msg_type   = SQMP_MSG_TYPE_AUTH_REQ;
    pkt->session_id = session->session_id;

    auth->username_len = (uint8_t)ulen;
    memcpy(auth->username,      username, ulen);
    memcpy(auth->password_hash, pw_hash,  SQMP_PASSWORD_HASH_LEN);
    auth->pubkey_len = 0;

    session->username_len = (uint8_t)ulen;
    memcpy(session->username, username, ulen);

    if (sqmp_stream_send(stream, buf, sizeof(buf)) != 0) {
        fprintf(stderr, "failed to send AUTH_REQ\n");
        return -1;
    }

    printf("AUTH_REQ sent for '%.*s'\n", (int)ulen, username);
    fflush(stdout);
    return 0;
}

int main(void)
{
    sqmp_session_t session = {0};
    session.state = SQMP_SESSION_STATE_HELLO;
    sem_init(&session.login_ready, 0, 0);

    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    sqmp_quic_config_t cfg = {
        .app_name        = "squimpchat-client",
        .idle_timeout_ms = 30000,
        .on_connected    = on_connected,
        .on_disconnected = on_disconnected,
        .on_stream_recv  = on_stream_recv,
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

    printf("Connecting to %s:%d...\n", SERVER_HOST, SERVER_PORT);
    fflush(stdout);

    sqmp_conn_t *conn = sqmp_quic_connect(ctx, CLIENT_ALPN, SERVER_HOST, SERVER_PORT);
    if (!conn) {
        fprintf(stderr, "connection failed\n");
        sqmp_quic_destroy(ctx);
        return 1;
    }
    sqmp_conn_set_user_data(conn, &session);

    sqmp_stream_t *stream = sqmp_stream_open(conn);
    if (!stream) {
        fprintf(stderr, "failed to open stream\n");
        sqmp_quic_disconnect(conn);
        sqmp_quic_destroy(ctx);
        return 1;
    }
    sqmp_stream_set_user_data(stream, &session);

    {
        uint8_t buf[sizeof(sqmp_pkt_t) + sizeof(sqmp_msg_hello_t)];
        memset(buf, 0, sizeof(buf));
        sqmp_pkt_t       *pkt = (sqmp_pkt_t *)buf;
        sqmp_msg_hello_t *msg = (sqmp_msg_hello_t *)pkt->msg;
        pkt->version          = 1;
        pkt->msg_type         = SQMP_MSG_TYPE_HELLO;
        msg->num_versions     = 1;
        msg->versions[0]      = 1;
        msg->selected_version = 1;
        msg->max_message_size = 65535;
        sqmp_stream_send(stream, buf, sizeof(buf));
    }

    while (sem_wait(&session.login_ready) == -1 && errno == EINTR && !g_interrupted)
        ;

    if (!g_interrupted)
        sqmp_login(stream, &session);

    while (!g_interrupted)
        pause();

    printf("\nInterrupted, disconnecting...\n");
    fflush(stdout);

    sqmp_quic_disconnect(conn);
    sqmp_quic_destroy(ctx);
    sem_destroy(&session.login_ready);
    return 0;
}
