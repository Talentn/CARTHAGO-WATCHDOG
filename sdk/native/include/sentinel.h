/* sentinel.h: Sentinel client SDK C ABI, version 1. Mirrors client/crates/sn-client-ffi.
 * Hand-written for Phase 0; cbindgen generates it (and is diffed against it) from Phase 1.
 *
 * Threading: sn_tick may be called from the game thread every frame; it never blocks.
 * Callbacks run on the SDK's own thread; keep them short and thread-safe. */
#ifndef SENTINEL_H
#define SENTINEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SN_ABI_VERSION 1u

typedef int32_t SnResult;
#define SN_OK 0
#define SN_ERR_INVALID_ARG 1
#define SN_ERR_NOT_INITIALIZED 2
#define SN_ERR_ALREADY_INITIALIZED 3
#define SN_ERR_BUFFER_TOO_SMALL 4
#define SN_ERR_NO_SESSION 5
#define SN_ERR_ABI_MISMATCH 6
#define SN_ERR_SESSION_FAILED 7
#define SN_ERR_INTERNAL 99

/* SnConfig.flags */
#define SN_FLAG_NO_TPM 1u /* force the software device key (trust_level 0) */
/* Process mitigation profile applied at init. Default: basic (no remote or low-integrity
 * image loads). Strict adds System32-first DLL search and disables legacy extension points
 * (AppInit DLLs, LSPs); validate it against the title's IMEs and overlays first. */
#define CARTHAGO_FLAG_NO_MITIGATIONS 2u
#define CARTHAGO_FLAG_STRICT_MITIGATIONS 4u
/* Disable the low-level mouse hook that counts injected input while the game has focus. */
#define CARTHAGO_FLAG_NO_INPUT_MONITOR 8u

/* Log levels */
#define SN_LOG_DEBUG 0
#define SN_LOG_INFO 1
#define SN_LOG_WARN 2
#define SN_LOG_ERROR 3

typedef enum SnActivity { SN_MENU = 0, SN_LOADING = 1, SN_IN_MATCH = 2, SN_IN_COMBAT = 3 } SnActivity;

/* SnStatus.state */
#define SN_STATE_IDLE 0
#define SN_STATE_CONNECTING 1
#define SN_STATE_ACTIVE 2
#define SN_STATE_KICKED 3
#define SN_STATE_FAILED 4
#define SN_STATE_DISCONNECTED 5

/* attest_flags bits (proto/README.md) */
#define SN_ATTEST_TPM_DEVICE_KEY (1ull << 0)
#define SN_ATTEST_DEVICE_KEY_CERTIFIED (1ull << 1)
#define SN_ATTEST_AK_BOUND_TO_EK (1ull << 2)
#define SN_ATTEST_QUOTE_VERIFIED (1ull << 3)
#define SN_ATTEST_SECURE_BOOT (1ull << 4)
#define SN_ATTEST_HVCI (1ull << 5)
#define SN_ATTEST_TEST_SIGNING_OFF (1ull << 6)
#define SN_ATTEST_KERNEL_DEBUG_OFF (1ull << 7)
#define SN_ATTEST_BOOT_DEBUG_OFF (1ull << 8)
#define SN_ATTEST_CODE_INTEGRITY (1ull << 9)
#define SN_ATTEST_EK_CERT_MATCHES (1ull << 10)
#define SN_ATTEST_EK_CHAIN_VERIFIED (1ull << 11)

typedef void (*SnLogFn)(int32_t level, const char* msg, void* user);
typedef void (*SnSessionCb)(SnResult result, uint32_t trust_level, uint64_t attest_flags, void* user);
typedef void (*SnKickCb)(const char* reason, void* user);

typedef struct SnConfig {
    uint32_t abi_version;  /* SN_ABI_VERSION */
    uint32_t struct_size;  /* sizeof(SnConfig) */
    const char* tenant_id;
    const char* build_id;
    const char* gateway_url;             /* Phase 0: ws://127.0.0.1:8750/v1/client */
    const char* server_identity_key_hex; /* pinned gateway identity key (64 hex chars) */
    SnLogFn log;                         /* optional */
    void* log_user;
    uint32_t flags;
} SnConfig;

typedef struct SnStatus {
    uint32_t struct_size; /* set to sizeof(SnStatus) before calling */
    uint32_t state;       /* SN_STATE_* */
    uint32_t trust_level;
    uint32_t reserved;
    uint64_t attest_flags;
    uint64_t heartbeats_sent;
    uint64_t heartbeats_acked;
    uint64_t last_ack_age_ms; /* UINT64_MAX if none yet */
    uint64_t sched_worker_cpu_ns;
    uint64_t sched_slices;
    uint64_t frames;
} SnStatus;

/* Returns immediately; scheduler and device identity start on the SDK thread. */
SnResult sn_init(const SnConfig* cfg);
/* Handshake with the gateway; on_ready runs on the SDK thread when it completes. */
SnResult sn_begin_session(const char* player_id_hash, SnSessionCb on_ready, void* user);
/* Copies the session token to forward to the game server. *len: in = buffer size,
 * out = token length (or the required size incl. NUL on SN_ERR_BUFFER_TOO_SMALL). */
SnResult sn_get_session_token(char* buf, size_t* len);
void sn_tick(void);
void sn_set_activity(SnActivity activity);
/* Heartbeats are automatic (jittered); this requests one immediately. */
SnResult sn_heartbeat_now(void);
SnResult sn_get_status(SnStatus* out);
void sn_set_kick_callback(SnKickCb cb, void* user);
void sn_shutdown(void);

#ifdef SN_DEV_HOOKS
/* Test-only (sentinel.dll built with feature dev-hooks): stop heartbeating, stay connected. */
void sn_dev_suppress_heartbeats(int32_t on);
#endif

#ifdef __cplusplus
}
#endif
#endif /* SENTINEL_H */
