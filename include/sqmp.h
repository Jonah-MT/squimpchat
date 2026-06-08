#pragma once

#include "msquic_wrapper.h"
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>

#define SQMP_USERNAME_MAX_LEN 32
#define SQMP_PASSWORD_HASH_LEN 32
#define SQMP_ERROR_DESC_MAX_LEN 128
#define SQMP_REGISTRY_MAX 64

typedef struct sqmp_session_s {
    uint8_t  state;
    uint32_t session_id;
    uint8_t  username_len;
    uint8_t  username[SQMP_USERNAME_MAX_LEN];
    sem_t    login_ready;

    sem_t    auth_done;
    uint8_t  auth_ok;
    uint8_t  client_pubkey[32];
    uint8_t  client_privkey[32];

    _Atomic(struct sqmp_stream_s *) auth_stream;
    _Atomic uint8_t                 auth_queued;
    _Atomic uint8_t                 conn_closed;

    uint8_t                 auth_username_len;
    uint8_t                 auth_username[SQMP_USERNAME_MAX_LEN];
    uint8_t                 auth_password_hash[SQMP_PASSWORD_HASH_LEN];
    uint8_t                 auth_pubkey[32];
    sem_t                   key_fetch_sem;
    uint8_t                 key_fetch_result[32];
    struct sqmp_session_s  *next;
} sqmp_session_t;

enum sqmp_session_state_e {
    SQMP_SESSION_STATE_CLOSED = 0,
    SQMP_SESSION_STATE_HELLO = 1,
    SQMP_SESSION_STATE_AUTH = 2,
    SQMP_SESSION_STATE_CONN_ESTABLISHED = 3,
    SQMP_SESSION_STATE_CLOSING = 4
};

typedef struct sqmp_pkt_s {
    uint8_t  version;
    uint8_t  msg_type;
    uint8_t  flags;
    uint32_t session_id;
    uint8_t  reserved[5];
    uint8_t  msg[];
} __attribute__((packed)) sqmp_pkt_t;

#define SQMP_PKT_FIXED_LEN 12

enum sqmp_msg_types_e {
    SQMP_MSG_TYPE_HELLO        = 0x01,
    SQMP_MSG_TYPE_HELLO_ACK    = 0x02,
    SQMP_MSG_TYPE_AUTH_REQ     = 0x03,
    SQMP_MSG_TYPE_AUTH_RESP    = 0x04,
    SQMP_MSG_TYPE_KEY_REQ      = 0x05,
    SQMP_MSG_TYPE_KEY_RESP     = 0x06,
    SQMP_MSG_TYPE_ERROR        = 0x07,
    SQMP_MSG_TYPE_BYE          = 0x08,
    SQMP_MSG_TYPE_CHAT_SEND    = 0x10,
    SQMP_MSG_TYPE_CHAT_DELIVER = 0x11,
    SQMP_MSG_TYPE_CHAT_ACK     = 0x12
};

enum sqmp_flags_e {
    SQMP_FLAG_ENCRYPTED     = 0x01,
    SQMP_FLAG_SYS_MSG       = 0x02,
    SQMP_FLAG_FRAGMENT      = 0x03,
    SQMP_FLAG_LAST_FRAGMENT = 0x04
};

typedef struct sqmp_msg_hello_s {
    uint8_t  num_versions;
    uint8_t  versions[8];
    uint8_t  selected_version;
    uint32_t max_message_size;
    uint8_t  reserved[2];
} __attribute__((packed)) sqmp_msg_hello_t;

typedef struct sqmp_msg_hello_ack_s {
    uint8_t  selected_version;
    uint32_t max_message_size;
    uint8_t  reserved[2];
} __attribute__((packed)) sqmp_msg_hello_ack_t;

typedef struct sqmp_msg_auth_req_s {
    uint8_t  username_len;
    uint8_t  username[SQMP_USERNAME_MAX_LEN];
    uint8_t  password_hash[SQMP_PASSWORD_HASH_LEN];
    uint16_t pubkey_len;
    uint8_t  public_key[];
} __attribute__((packed)) sqmp_msg_auth_req_t;

typedef struct sqmp_msg_auth_resp_s {
    uint8_t  status;
    uint32_t session_id;
    uint8_t  reserved[3];
} __attribute__((packed)) sqmp_msg_auth_resp_t;

typedef struct sqmp_msg_key_req_s {
    uint8_t  username_len;
    uint8_t  username[SQMP_USERNAME_MAX_LEN];
} __attribute__((packed)) sqmp_msg_key_req_t;

typedef struct sqmp_msg_key_resp_s {
    uint8_t  username_len;
    uint8_t  username[SQMP_USERNAME_MAX_LEN];
    uint16_t pubkey_len;
    uint8_t  public_key[];
} __attribute__((packed)) sqmp_msg_key_resp_t;

typedef struct sqmp_msg_error_s {
    uint8_t  error_code;
    uint8_t  desc_len;
    uint8_t  description[SQMP_ERROR_DESC_MAX_LEN];
} __attribute__((packed)) sqmp_msg_error_t;

enum sqmp_error_code_e {
    SQMP_ERROR_CODE_GENERAL          = 0x00,
    SQMP_ERROR_CODE_USER_NOT_FOUND   = 0x01,
    SQMP_ERROR_CODE_COULD_NOT_SEND   = 0x02,
    SQMP_ERROR_CODE_VERSION_MISMATCH = 0x03,
    SQMP_ERROR_CODE_UNEXPECTED_MSG   = 0x04,
};

typedef struct sqmp_msg_chat_send_s {
    uint8_t  recipient_len;
    uint8_t  recipient[SQMP_USERNAME_MAX_LEN];
    uint16_t enc_key_len;
    uint8_t  encrypted_key[256];
    uint8_t  nonce[12];
    uint32_t ciphertext_len;
    uint8_t  ciphertext[];
} __attribute__((packed)) sqmp_msg_chat_send_t;

typedef struct sqmp_msg_chat_deliver_s {
    uint8_t  sender_len;
    uint8_t  sender[SQMP_USERNAME_MAX_LEN];
    uint16_t enc_key_len;
    uint8_t  encrypted_key[256];
    uint8_t  nonce[12];
    uint32_t ciphertext_len;
    uint8_t  ciphertext[];
} __attribute__((packed)) sqmp_msg_chat_deliver_t;

typedef struct sqmp_msg_chat_ack_s {
    uint8_t  status;
    uint64_t timestamp;
    uint8_t  sender_len;
    uint8_t  sender[SQMP_USERNAME_MAX_LEN];
    uint8_t  reserved[2];
} __attribute__((packed)) sqmp_msg_chat_ack_t;

enum sqmp_chat_ack_status_e {
    SQMP_CHAT_ACK_STATUS_DELIVERED = 0x00,
    SQMP_CHAT_ACK_STATUS_QUEUED    = 0x01,
    SQMP_CHAT_ACK_STATUS_FAILURE   = 0x02
};

enum sqmp_auth_status_e {
    SQMP_AUTH_STATUS_OK      = 0x00,
    SQMP_AUTH_STATUS_INVALID = 0x01,
};

void sqmp_process_hello(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt);
void sqmp_process_hello_ack(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt);
void sqmp_process_auth_req(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt);
void sqmp_process_auth_resp(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt);
void sqmp_process_chat_deliver(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt);
void sqmp_process_chat_send(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt);
void sqmp_process_key_req(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt);
void sqmp_process_key_resp(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt);
void sqmp_process_bye(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt);
void sqmp_process_error(sqmp_stream_t *stream, sqmp_session_t *session, sqmp_pkt_t *pkt);
void sqmp_send_bye(sqmp_stream_t *stream, sqmp_session_t *session);
void sqmp_send_error(sqmp_stream_t *stream, sqmp_session_t *session, uint8_t code, const char *desc);
void sqmp_registry_send_bye_all(void);
void sqmp_registry_shutdown_connections(void);

void sqmp_auth_queue_init(void);
sqmp_session_t *sqmp_auth_queue_dequeue(void);

int sqmp_registry_add(const uint8_t *uname, uint8_t ulen, sqmp_stream_t *stream, const uint8_t *pubkey);
void sqmp_registry_remove(const uint8_t *uname, uint8_t ulen);
sqmp_stream_t *sqmp_registry_find  (const uint8_t *uname, uint8_t ulen);
int sqmp_registry_get_pubkey(const uint8_t *uname, uint8_t ulen, uint8_t pubkey_out[32]);

void sqmp_dbg_recv_pkt(const sqmp_pkt_t *pkt);
