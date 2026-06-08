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
#include <readline/readline.h>

static volatile sig_atomic_t g_interrupted;
static pthread_t             g_main_thread;
static _Atomic int           g_conn_alive = 1;
static _Atomic int           g_readline_active = 0;

/*
 * sig_handler
 * Sets the interrupted flag on SIGINT/SIGTERM.
 *
 * in:  sig - signal number (unused)
 */
static void sig_handler(int sig)
{
    (void)sig;
    g_interrupted = 1;
}

/*
 * rl_interrupt_hook
 * readline event hook called every 100ms. Forces readline to return
 * immediately when the interrupted flag is set.
 *
 * out: 0 (always)
 */
static int rl_interrupt_hook(void)
{
    if (g_interrupted) {
        rl_replace_line("", 0);
        rl_done = 1;
    }
    return 0;
}

/*
 * on_connected
 * Prints message when the QUIC connection is established.
 *
 * in:  conn - the new connection (unused)
 */
static void on_connected(sqmp_conn_t *conn)
{
    (void)conn;
    printf("QUIC connection established\n");
    fflush(stdout);
}

/*
 * on_stream_recv
 * Sends an incoming packet to the appropriate handler.
 *
 * in:  stream - stream the data arrived on
 *      data   - raw packet bytes
 *      len    - number of bytes
 */
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

/*
 * on_disconnected
 * Called when the server terminates the connection. Wakes the main
 * thread so it can exit cleanly.
 *
 * in:  conn - the connection that dropped (unused)
 */
static void on_disconnected(sqmp_conn_t *conn)
{
    (void)conn;
    int rl_active = atomic_load(&g_readline_active);
    if (rl_active) rl_clear_visible_line();
    printf("Disconnected from server\n");
    fflush(stdout);
    if (rl_active) rl_forced_update_display();
    atomic_store(&g_conn_alive, 0);
    g_interrupted = 1;
    pthread_kill(g_main_thread, SIGINT);
}

/*
 * sqmp_login
 * Prompts for username and password, generates an X25519 keypair, and
 * sends AUTH_REQ to the server.
 *
 * in:  stream  - stream to send on
 *      session - session to populate with login info
 * out: 0 on success, -1 on failure
 */
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

    fflush(stdout);
    return 0;
}

/*
 * sqmp_process_bye
 * Handler for MSG_BYE. Echoes a BYE back and wakes the main thread
 * to begin shutdown.
 *
 * in:  stream, session, pkt - standard handler args
 */
void sqmp_process_bye(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt)
{
    (void)pkt;
    sqmp_send_bye(stream, session);
    g_interrupted = 1;
    pthread_kill(g_main_thread, SIGINT);
}

/*
 * encrypt_chat
 * Encrypts plaintext using X25519 ECDH + AES-256-GCM and recipient's
 * public key. Generates an ephemeral keypair per message; the public
 * key is written to ephemeral_pub_out so the recipient can derive the
 * same AES key.
 *
 * in:  peer_pubkey        - recipient's 32-byte X25519 public key
 *      plaintext          - message to encrypt
 *      plaintext_len      - length of plaintext
 *      ephemeral_pub_out  - receives the ephemeral public key (32 bytes)
 *      nonce_out          - receives the random nonce (12 bytes)
 *      ciphertext_out     - buffer for output (caller allocates msglen+16)
 *      ciphertext_len_out - receives the final ciphertext length
 * out: 0 on success, -1 on failure
 */
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

/*
 * decrypt_chat
 * Decrypts a received AES-256-GCM ciphertext using our private key and
 * the sender's ephemeral public key.
 *
 * in:  privkey           - our 32-byte X25519 private key
 *      ephemeral_pub     - sender's ephemeral public key (32 bytes)
 *      nonce             - 12-byte nonce
 *      ciphertext        - ciphertext with 16-byte auth tag appended
 *      ciphertext_len    - total length including tag
 *      plaintext_out     - buffer for decrypted output
 *      plaintext_len_out - receives the plaintext length
 * out: 0 on success, -1 on failure (including auth tag mismatch)
 */
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

/*
 * sqmp_process_chat_deliver
 * Handler for MSG_CHAT_DELIVER. Decrypts and prints the incoming
 * message without disrupting whatever the user is typing.
 *
 * in:  stream, session, pkt - standard handler args
 */
void sqmp_process_chat_deliver(sqmp_stream_t *stream, sqmp_session_t *session,
                               sqmp_pkt_t *pkt)
{
    (void)stream;
    sqmp_msg_chat_deliver_t *msg = (sqmp_msg_chat_deliver_t *)pkt->msg;

    if (session->state != SQMP_SESSION_STATE_CONN_ESTABLISHED) {
        fprintf(stderr, "CHAT_DELIVER in unexpected state %d\n", session->state);
        return;
    }

    int rl_active = atomic_load(&g_readline_active);
    if (rl_active) rl_clear_visible_line();

    printf("[from: %.*s] ", (int)msg->sender_len, msg->sender);

    if (msg->enc_key_len != 32 || msg->ciphertext_len < 16) {
        printf("ERROR: cannot decrypt\n");
        fflush(stdout);
        if (rl_active) rl_forced_update_display();
        return;
    }

    uint32_t plaintext_len = msg->ciphertext_len - 16;
    uint8_t *plaintext     = malloc(plaintext_len + 1);
    if (!plaintext) {
        printf("ERROR: alloc error\n");
        fflush(stdout);
        if (rl_active) rl_forced_update_display();
        return;
    }

    if (decrypt_chat(session->client_privkey, msg->encrypted_key, msg->nonce,
                     msg->ciphertext, msg->ciphertext_len,
                     plaintext, &plaintext_len) == 0) {
        plaintext[plaintext_len] = '\0';
        printf("%.*s\n", (int)plaintext_len, (char *)plaintext);
    } else {
        printf("ERROR: decrypt failed\n");
    }
    free(plaintext);
    fflush(stdout);
    if (rl_active) rl_forced_update_display();
}

/*
 * send_chat
 * Fetches the recipient's public key from the server, encrypts the
 * message, and sends it as MSG_CHAT_SEND. Blocks up to 5 seconds
 * waiting for the key response.
 *
 * in:  stream        - stream to send on
 *      session       - current session
 *      recipient     - recipient username
 *      recipient_len - length of recipient username
 *      msg           - message text
 *      msglen        - length of message
 * out: 0 on success, -1 on failure
 */
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

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Not enough arguments provided.\nUsage: ./client <hostname>\n");
        return 1;
    } else if (argc > 2) {
        fprintf(stderr, "Too many arguments.\nUsage: ./client <hostname>\n");
        return 1;
    }
    char *host = argv[1];

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

    printf("Connecting to %s:%d...\n", host, SERVER_PORT);
    fflush(stdout);

    sqmp_conn_t *conn = sqmp_quic_connect(ctx, CLIENT_ALPN, host, SERVER_PORT);
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

        printf("\n\n");
        printf("-----------------------------------------------------\n");
        printf(" ___            _             ___ _         _     \n");
        printf("/ __| __ _ _  _(_)_ __  _ __ / __| |_  __ _| |_   \n");
        printf("\\__ \\/ _` | || | | '  \\| '_ \\ (__| ' \\/ _` |  _|  \n");
        printf("|___/\\__, |\\_,_|_|_|_|_| .__/\\___|_||_\\__,_|\\__|  \n");
        printf("        |_|            |_|                        \n");
        printf("-----------------------------------------------------\n");
        printf("Logged in. Type '<username> <message>' and press Enter to send:\n");
        printf("Enter \"exit\", enter \"quit\", or press Ctrl+C to exit\n");
        fflush(stdout);

        rl_catch_signals = 0;
        rl_event_hook    = rl_interrupt_hook;
        rl_set_keyboard_input_timeout(100000);
        atomic_store(&g_readline_active, 1);

        char *line = NULL;
        while (!g_interrupted) {
            line = readline("> ");
            if (!line) break;

            printf("\033[1A\033[2K\r");
            fflush(stdout);

            size_t len = strlen(line);
            if (len == 0) { free(line); line = NULL; continue; }

            if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
                free(line);
                line = NULL;
                break;
            }

            char *space = strchr(line, ' ');
            if (!space || space == line || *(space + 1) == '\0') {
                printf("Usage: <username> <message>\n");
                fflush(stdout);
                free(line); line = NULL;
                continue;
            }

            size_t      recipient_len = (size_t)(space - line);
            const char *msg           = space + 1;
            size_t      msglen        = len - recipient_len - 1;

            if (recipient_len > SQMP_USERNAME_MAX_LEN) {
                fprintf(stderr, "recipient name too long\n");
                free(line); line = NULL;
                continue;
            }

            printf("[to: %.*s] %s\n", (int)recipient_len, line, msg);
            fflush(stdout);

            if (send_chat(stream, &session, line, recipient_len, msg, msglen) != 0)
                fprintf(stderr, "failed to send message\n");

            free(line);
            line = NULL;
        }
        if (line) free(line);
        atomic_store(&g_readline_active, 0);
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
