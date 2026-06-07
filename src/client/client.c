#include "client.h"
#include "sqmp.h"
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include "debug.h"
#include <unistd.h>

static volatile sig_atomic_t g_interrupted;
static pthread_t             g_main_thread;
static _Atomic int           g_conn_alive = 1;

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

    sqmp_dbg_recv_pkt(pkt);
    switch (pkt->msg_type) {
        case SQMP_MSG_TYPE_HELLO_ACK:
            sqmp_process_hello_ack(stream, session, pkt);
            break;
        case SQMP_MSG_TYPE_AUTH_RESP:
            sqmp_process_auth_resp(stream, session, pkt);
            break;
        case SQMP_MSG_TYPE_KEY_RESP:
            sqmp_process_key_resp(stream, session, pkt);
            break;
        case SQMP_MSG_TYPE_CHAT_DELIVER:
            sqmp_process_chat_deliver(stream, session, pkt);
            break;
        case SQMP_MSG_TYPE_BYE:
            sqmp_process_bye(stream, session, pkt);
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
    atomic_store(&g_conn_alive, 0);
    g_interrupted = 1;
    pthread_kill(g_main_thread, SIGINT);
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

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return -1;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return -1;
    }
    EVP_PKEY_CTX_free(kctx);
    size_t klen = 32;
    EVP_PKEY_get_raw_public_key(pkey, session->client_pubkey, &klen);
    klen = 32;
    EVP_PKEY_get_raw_private_key(pkey, session->client_privkey, &klen);
    EVP_PKEY_free(pkey);

    uint8_t buf[sizeof(sqmp_pkt_t) + sizeof(sqmp_msg_auth_req_t) + 32];
    memset(buf, 0, sizeof(buf));
    sqmp_pkt_t          *pkt  = (sqmp_pkt_t *)buf;
    sqmp_msg_auth_req_t *auth = (sqmp_msg_auth_req_t *)pkt->msg;

    pkt->version    = 1;
    pkt->msg_type   = SQMP_MSG_TYPE_AUTH_REQ;
    pkt->session_id = session->session_id;

    auth->username_len = (uint8_t)ulen;
    memcpy(auth->username,      username, ulen);
    memcpy(auth->password_hash, pw_hash,  SQMP_PASSWORD_HASH_LEN);
    auth->pubkey_len = 32;
    memcpy(auth->public_key, session->client_pubkey, 32);

    session->username_len = (uint8_t)ulen;
    memcpy(session->username, username, ulen);

    if (sqmp_stream_send(stream, buf, sizeof(buf)) != 0) {
        fprintf(stderr, "failed to send AUTH_REQ\n");
        return -1;
    }
    dbg_printf("[sent] MSG_AUTH_REQ (user='%.*s')\n", (int)ulen, username);

    printf("AUTH_REQ sent for '%.*s'\n", (int)ulen, username);
    fflush(stdout);
    return 0;
}

void sqmp_process_bye(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)pkt;
    sqmp_send_bye(stream, session);
    g_interrupted = 1;
    pthread_kill(g_main_thread, SIGINT);
}

static int encrypt_chat(const uint8_t *peer_pubkey,
                        const char *plaintext, size_t plaintext_len,
                        uint8_t ephemeral_pub_out[32],
                        uint8_t nonce_out[12],
                        uint8_t *ciphertext_out,
                        uint32_t *ciphertext_len_out)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return -1;
    }
    EVP_PKEY *ephemeral = NULL;
    if (EVP_PKEY_keygen(kctx, &ephemeral) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return -1;
    }
    EVP_PKEY_CTX_free(kctx);

    size_t klen = 32;
    EVP_PKEY_get_raw_public_key(ephemeral, ephemeral_pub_out, &klen);

    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pubkey, 32);
    if (!peer) {
        EVP_PKEY_free(ephemeral);
        return -1;
    }

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(ephemeral, NULL);
    EVP_PKEY_free(ephemeral);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, peer) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer);
        return -1;
    }
    EVP_PKEY_free(peer);

    uint8_t shared[32];
    size_t  slen = 32;
    if (EVP_PKEY_derive(dctx, shared, &slen) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        return -1;
    }
    EVP_PKEY_CTX_free(dctx);

    uint8_t aes_key[32];
    SHA256(shared, 32, aes_key);
    memset(shared, 0, 32);

    if (RAND_bytes(nonce_out, 12) != 1)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int outlen = 0, final_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)          != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, nonce_out)                != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext_out, &outlen,
                          (const uint8_t *)plaintext, (int)plaintext_len)      != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext_out + outlen, &final_len)          != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                            ciphertext_out + outlen + final_len)               != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);

    *ciphertext_len_out = (uint32_t)(outlen + final_len + 16);
    return 0;
}

static int decrypt_chat(const uint8_t *privkey,
                        const uint8_t *ephemeral_pub,
                        const uint8_t nonce[12],
                        const uint8_t *ciphertext, uint32_t ciphertext_len,
                        uint8_t *plaintext_out,
                        uint32_t *plaintext_len_out)
{
    if (ciphertext_len < 16) return -1;

    EVP_PKEY *our_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, privkey, 32);
    if (!our_key) return -1;

    EVP_PKEY *sender_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, ephemeral_pub, 32);
    if (!sender_pub) {
        EVP_PKEY_free(our_key);
        return -1;
    }

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(our_key, NULL);
    EVP_PKEY_free(our_key);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, sender_pub) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(sender_pub);
        return -1;
    }
    EVP_PKEY_free(sender_pub);

    uint8_t shared[32];
    size_t  slen = 32;
    if (EVP_PKEY_derive(dctx, shared, &slen) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        return -1;
    }
    EVP_PKEY_CTX_free(dctx);

    uint8_t aes_key[32];
    SHA256(shared, 32, aes_key);
    memset(shared, 0, 32);

    uint32_t  data_len = ciphertext_len - 16;
    void     *tag      = (void *)(uintptr_t)(ciphertext + data_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int outlen = 0, final_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)        != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, nonce)                  != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)             != 1 ||
        EVP_DecryptUpdate(ctx, plaintext_out, &outlen,
                          ciphertext, (int)data_len)                         != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext_out + outlen, &final_len)         != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);

    *plaintext_len_out = (uint32_t)(outlen + final_len);
    return 0;
}

void sqmp_process_chat_deliver(sqmp_stream_t *stream, sqmp_session_t *session,
                               sqmp_pkt_t *pkt)
{
    (void)stream;
    sqmp_msg_chat_deliver_t *msg = (sqmp_msg_chat_deliver_t *)pkt->msg;

    if (session->state != SQMP_SESSION_STATE_CONN_ESTABLISHED) {
        fprintf(stderr, "CHAT_DELIVER in unexpected state %d\n", session->state);
        return;
    }

    printf("[from: %.*s] ciphertext: ", (int)msg->sender_len, msg->sender);
    for (uint32_t i = 0; i < msg->ciphertext_len; i++)
        printf("%02x", msg->ciphertext[i]);

    if (msg->enc_key_len != 32 || msg->ciphertext_len < 16) {
        printf(" text: (cannot decrypt)\n");
        fflush(stdout);
        return;
    }

    uint32_t plaintext_len = msg->ciphertext_len - 16;
    uint8_t *plaintext     = malloc(plaintext_len + 1);
    if (!plaintext) {
        printf(" text: (alloc error)\n");
        fflush(stdout);
        return;
    }

    if (decrypt_chat(session->client_privkey, msg->encrypted_key, msg->nonce,
                     msg->ciphertext, msg->ciphertext_len,
                     plaintext, &plaintext_len) == 0) {
        plaintext[plaintext_len] = '\0';
        printf(" text: %.*s\n", (int)plaintext_len, (char *)plaintext);
    } else {
        printf(" text: (decrypt failed)\n");
    }
    free(plaintext);
    fflush(stdout);
}

static int send_chat(sqmp_stream_t *stream, sqmp_session_t *session,
                     const char *recipient, size_t recipient_len,
                     const char *msg, size_t msglen)
{
    uint8_t keybuf[sizeof(sqmp_pkt_t) + sizeof(sqmp_msg_key_req_t)];
    memset(keybuf, 0, sizeof(keybuf));
    sqmp_pkt_t         *kpkt = (sqmp_pkt_t *)keybuf;
    sqmp_msg_key_req_t *kreq = (sqmp_msg_key_req_t *)kpkt->msg;
    kpkt->version      = 1;
    kpkt->msg_type     = SQMP_MSG_TYPE_KEY_REQ;
    kpkt->session_id   = session->session_id;
    kreq->username_len = (uint8_t)recipient_len;
    memcpy(kreq->username, recipient, recipient_len);
    sqmp_stream_send(stream, keybuf, sizeof(keybuf));
    dbg_printf("[sent] MSG_KEY_REQ (for='%.*s')\n", (int)recipient_len, recipient);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    if (sem_timedwait(&session->key_fetch_sem, &ts) != 0) {
        fprintf(stderr, "key fetch timed out for '%.*s'\n",
                (int)recipient_len, recipient);
        return -1;
    }

    static const uint8_t zeros[32] = {0};
    if (memcmp(session->key_fetch_result, zeros, 32) == 0) {
        fprintf(stderr, "user '%.*s' not found or has no key\n",
                (int)recipient_len, recipient);
        return -1;
    }

    uint8_t  ephemeral_pub[32];
    uint8_t  nonce[12];
    uint8_t *ciphertext = malloc(msglen + 16);
    if (!ciphertext) return -1;
    uint32_t ciphertext_len;

    if (encrypt_chat(session->key_fetch_result, msg, msglen,
                     ephemeral_pub, nonce, ciphertext, &ciphertext_len) != 0) {
        free(ciphertext);
        return -1;
    }

    size_t   pktlen = sizeof(sqmp_pkt_t) + sizeof(sqmp_msg_chat_send_t) + ciphertext_len;
    uint8_t *buf    = calloc(1, pktlen);
    if (!buf) { free(ciphertext); return -1; }

    sqmp_pkt_t           *pkt  = (sqmp_pkt_t *)buf;
    sqmp_msg_chat_send_t *chat = (sqmp_msg_chat_send_t *)pkt->msg;

    pkt->version    = 1;
    pkt->msg_type   = SQMP_MSG_TYPE_CHAT_SEND;
    pkt->session_id = session->session_id;

    chat->recipient_len  = (uint8_t)recipient_len;
    memcpy(chat->recipient, recipient, recipient_len);
    chat->enc_key_len    = 32;
    memcpy(chat->encrypted_key, ephemeral_pub, 32);
    memcpy(chat->nonce, nonce, 12);
    chat->ciphertext_len = ciphertext_len;
    memcpy(chat->ciphertext, ciphertext, ciphertext_len);

    free(ciphertext);
    int ret = sqmp_stream_send(stream, buf, pktlen);
    dbg_printf("[sent] MSG_CHAT_SEND (to='%.*s' ciphertext_len=%u)\n",
               (int)recipient_len, recipient, ciphertext_len);
    free(buf);
    return ret;
}


/* --------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------*/

int main(void)
{
    sqmp_session_t session = {0};
    session.state = SQMP_SESSION_STATE_HELLO;
    sem_init(&session.login_ready, 0, 0);
    sem_init(&session.auth_done, 0, 0);
    sem_init(&session.key_fetch_sem, 0, 0);

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

    g_main_thread = pthread_self();

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
        dbg_printf("[sent] MSG_HELLO\n");
    }

    while (sem_wait(&session.login_ready) == -1 && errno == EINTR && !g_interrupted)
        ;

    if (!g_interrupted)
        sqmp_login(stream, &session);

    while (sem_wait(&session.auth_done) == -1 && errno == EINTR && !g_interrupted)
        ;

    if (!g_interrupted && session.auth_ok) {
        printf("Logged in. Type messages and press Enter to send:\n");
        fflush(stdout);

        printf("Usage: <username> <message>\n");
        fflush(stdout);

        char line[1024];
        while (!g_interrupted) {
            if (!fgets(line, sizeof(line), stdin)) break;
            if (g_interrupted) break;

            size_t len = strlen(line);
            if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
            if (len == 0) continue;

            char *space = strchr(line, ' ');
            if (!space || space == line || *(space + 1) == '\0') {
                printf("Usage: <username> <message>\n");
                fflush(stdout);
                continue;
            }

            size_t      recipient_len = (size_t)(space - line);
            const char *msg           = space + 1;
            size_t      msglen        = len - recipient_len - 1;

            if (recipient_len > SQMP_USERNAME_MAX_LEN) {
                fprintf(stderr, "recipient name too long\n");
                continue;
            }

            if (send_chat(stream, &session, line, recipient_len, msg, msglen) != 0)
                fprintf(stderr, "failed to send message\n");
        }
    }

    printf("\nDisconnecting...\n");
    fflush(stdout);

    if (atomic_load(&g_conn_alive))
        sqmp_send_bye(stream, &session);
    sqmp_quic_disconnect(conn);
    sqmp_quic_destroy(ctx);
    sem_destroy(&session.login_ready);
    sem_destroy(&session.auth_done);
    sem_destroy(&session.key_fetch_sem);
    return 0;
}
