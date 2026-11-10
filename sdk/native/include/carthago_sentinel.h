/* carthago_sentinel.h: Carthago Sentinel, the Carthago Watchdog client SDK C ABI, version 1. Mirrors client/crates/carthago-sentinel.
 * Hand-written for Phase 0; cbindgen generates it (and is diffed against it) from Phase 1.
 *
 * Threading: carthago_tick may be called from the game thread every frame; it never blocks.
 * Callbacks run on the SDK's own thread; keep them short and thread-safe. */
#ifndef CARTHAGO_SENTINEL_H
#define CARTHAGO_SENTINEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CARTHAGO_ABI_VERSION 1u

typedef int32_t CarthagoResult;
#define CARTHAGO_OK 0
#define CARTHAGO_ERR_INVALID_ARG 1
#define CARTHAGO_ERR_NOT_INITIALIZED 2
#define CARTHAGO_ERR_ALREADY_INITIALIZED 3
#define CARTHAGO_ERR_BUFFER_TOO_SMALL 4
#define CARTHAGO_ERR_NO_SESSION 5
#define CARTHAGO_ERR_ABI_MISMATCH 6
#define CARTHAGO_ERR_SESSION_FAILED 7
#define CARTHAGO_ERR_INTERNAL 99

/* CarthagoConfig.flags */
#define CARTHAGO_FLAG_NO_TPM 1u /* force the software device key (trust_level 0) */
/* Process mitigation profile applied at init. Default: basic (no remote or low-integrity
 * image loads). Strict adds System32-first DLL search and disables legacy extension points
 * (AppInit DLLs, LSPs); validate it against the title's IMEs and overlays first. */
#define CARTHAGO_FLAG_NO_MITIGATIONS 2u
#define CARTHAGO_FLAG_STRICT_MITIGATIONS 4u
/* Disable the low-level mouse hook that counts injected input while the game has focus. */
#define CARTHAGO_FLAG_NO_INPUT_MONITOR 8u

/* Log levels */
#define CARTHAGO_LOG_DEBUG 0
#define CARTHAGO_LOG_INFO 1
#define CARTHAGO_LOG_WARN 2
#define CARTHAGO_LOG_ERROR 3

typedef enum CarthagoActivity { CARTHAGO_MENU = 0, CARTHAGO_LOADING = 1, CARTHAGO_IN_MATCH = 2, CARTHAGO_IN_COMBAT = 3 } CarthagoActivity;

/* CarthagoStatus.state */
#define CARTHAGO_STATE_IDLE 0
#define CARTHAGO_STATE_CONNECTING 1
#define CARTHAGO_STATE_ACTIVE 2
#define CARTHAGO_STATE_KICKED 3
#define CARTHAGO_STATE_FAILED 4
#define CARTHAGO_STATE_DISCONNECTED 5

/* attest_flags bits (proto/README.md) */
#define CARTHAGO_ATTEST_TPM_DEVICE_KEY (1ull << 0)
#define CARTHAGO_ATTEST_DEVICE_KEY_CERTIFIED (1ull << 1)
#define CARTHAGO_ATTEST_AK_BOUND_TO_EK (1ull << 2)
#define CARTHAGO_ATTEST_QUOTE_VERIFIED (1ull << 3)
#define CARTHAGO_ATTEST_SECURE_BOOT (1ull << 4)
#define CARTHAGO_ATTEST_HVCI (1ull << 5)
#define CARTHAGO_ATTEST_TEST_SIGNING_OFF (1ull << 6)
#define CARTHAGO_ATTEST_KERNEL_DEBUG_OFF (1ull << 7)
#define CARTHAGO_ATTEST_BOOT_DEBUG_OFF (1ull << 8)
#define CARTHAGO_ATTEST_CODE_INTEGRITY (1ull << 9)
#define CARTHAGO_ATTEST_EK_CERT_MATCHES (1ull << 10)
#define CARTHAGO_ATTEST_EK_CHAIN_VERIFIED (1ull << 11)
#define CARTHAGO_ATTEST_EK_CHAIN_UNKNOWN_VENDOR (1ull << 12)
#define CARTHAGO_ATTEST_EK_CHAIN_INVALID (1ull << 13)

typedef void (*CarthagoLogFn)(int32_t level, const char* msg, void* user);
typedef void (*CarthagoSessionCb)(CarthagoResult result, uint32_t trust_level, uint64_t attest_flags, void* user);
typedef void (*CarthagoKickCb)(const char* reason, void* user);

typedef struct CarthagoConfig {
    uint32_t abi_version;  /* CARTHAGO_ABI_VERSION */
    uint32_t struct_size;  /* sizeof(CarthagoConfig) */
    const char* tenant_id;
    const char* build_id;
    const char* gateway_url;             /* wss://host:port/v1/client, or ws:// on loopback only */
    const char* server_identity_key_hex; /* pinned gateway identity key (64 hex chars) */
    CarthagoLogFn log;                   /* optional */
    void* log_user;
    uint32_t flags;
    /* Pinned gateway TLS keys: comma-separated hex SHA-256 of the certificate's
     * SubjectPublicKeyInfo (current, then backup). Required for wss://; NULL for ws://. */
    const char* tls_pins_hex;
} CarthagoConfig;

typedef struct CarthagoStatus {
    uint32_t struct_size; /* set to sizeof(CarthagoStatus) before calling */
    uint32_t state;       /* CARTHAGO_STATE_* */
    uint32_t trust_level;
    uint32_t reserved;
    uint64_t attest_flags;
    uint64_t heartbeats_sent;
    uint64_t heartbeats_acked;
    uint64_t last_ack_age_ms; /* UINT64_MAX if none yet */
    uint64_t sched_worker_cpu_ns;
    uint64_t sched_slices;
    uint64_t frames;
} CarthagoStatus;

/* Returns immediately; scheduler and device identity start on the SDK thread. */
CarthagoResult carthago_init(const CarthagoConfig* cfg);
/* Handshake with the gateway; on_ready runs on the SDK thread when it completes. */
CarthagoResult carthago_begin_session(const char* player_id_hash, CarthagoSessionCb on_ready, void* user);
/* Copies the session token to forward to the game server. *len: in = buffer size,
 * out = token length (or the required size incl. NUL on CARTHAGO_ERR_BUFFER_TOO_SMALL). */
CarthagoResult carthago_get_session_token(char* buf, size_t* len);
void carthago_tick(void);
void carthago_set_activity(CarthagoActivity activity);
/* Heartbeats are automatic (jittered); this requests one immediately. */
CarthagoResult carthago_heartbeat_now(void);
CarthagoResult carthago_get_status(CarthagoStatus* out);
void carthago_set_kick_callback(CarthagoKickCb cb, void* user);
void carthago_shutdown(void);

#ifdef CARTHAGO_DEV_HOOKS
/* Test-only (carthago_sentinel.dll built with feature dev-hooks): stop heartbeating, stay connected. */
void carthago_dev_suppress_heartbeats(int32_t on);
#endif

#ifdef __cplusplus
}
#endif
#endif /* CARTHAGO_SENTINEL_H */
