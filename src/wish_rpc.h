#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "bson.h"

/** 
 * A generic RPC client and server implementation 
 */

typedef int32_t wish_rpc_id_t;

struct wish_rpc_server;
struct wish_rpc_context;

#define MAX_RPC_OP_LEN 48
#define MAX_RPC_SERVER_NAME_LEN 16
/* This defines the maximum length of an RPC error message */
#define WISH_RPC_ERR_MSG_MAX_LEN 256

typedef void (*rpc_server_send_cb)(struct wish_rpc_context* req, const bson* bs);

/**
 * Request context for wish_rpc_server
 */
typedef struct wish_rpc_context {
    /** Pointer to RPC Server */
    struct wish_rpc_server* server;
    /** 
     * Operator 
     * 
     * The operator string is used to select the handler registered in the server
     */
    char op[MAX_RPC_OP_LEN];
    /**
     * Arguments for RPC command
     */
    const char* args;
    /** Request ID */
    int id;
    /** 
     * This field is for saving local service id, used in following situations:
     *      -when handling a "core app" rpc to determine which service called 
     *      the RPC
     *      -in mist device app, the local service which is the destination of an incoming Mist RPC command is saved here so that the RPC handler can use it for determining which mist device is  the recipient of the RPC 
     */
    uint8_t local_wsid[32];
    /** 
     * The originating wish context of the message, used in core rpc
     * server, send_op_handler(). 
     */
    void *ctx;
    /** Pointer to the wanted context structure  */
    void *context; 
    /** Send function context passed as the first argument to the send function */
    void* send_context;
    /** If non-null this callback is called when a request is terminated */
    void (*end)(struct wish_rpc_context *req);
    /** list pointer */
    struct wish_rpc_context* next;
} rpc_server_req;

struct wish_rpc_entry;

typedef void (*rpc_client_callback)(struct wish_rpc_entry* req, void *ctx, const uint8_t *payload, size_t payload_len);

typedef void (*rpc_op_handler)(rpc_server_req* rpc_ctx, const uint8_t* args);


/**
 * Access control decision callback
 * 
 * Called in rpc_acl_handler implementation.
 * 
 * decision(true, NULL)
 * decision(true, BSON({data: ['read','write','invoke']}))
 * decision(false, NULL)
 * 
 */
typedef void (*rpc_acl_check_decision_cb)(rpc_server_req* req, bool allowed);

/**
 * Access control plug-in function
 * 
 * Add to WishRpc using wish_rpc_server_set_acl(rpc_acl_handler my_acl_checker)
 * 
 * @resource Resource identifier eg. ucp#model.battery.level
 * @permission Permission name eg. "read", "write", "send", "call" or "access"
 * @ctx Context for acl handler, eg. wish_protocol_peer_t*
 * @decision Callback for handler to call when it has decided permissions i.e. decision(true, BSON(['read', 'write'])
 */
typedef void (*rpc_acl_check_handler)(rpc_server_req* req, const uint8_t* resource, const uint8_t* permission, void* ctx, rpc_acl_check_decision_cb decision);

struct wish_rpc_client;

typedef struct wish_rpc_entry {
    struct wish_rpc_client* client;
    wish_rpc_id_t id;
    rpc_client_callback cb;
    void* cb_context;
    rpc_client_callback passthru_cb;
    int passthru_id;
    /** used for storing peer pointer in passthrough. This field should probably should be removed when introducing separate rpc_clients for each peer */
    void* passthru_ctx;
    /** used for storing Mist pointer in nodejs addon */
    void* passthru_ctx2; 
    struct wish_rpc_entry *next;
    bool err;
} rpc_client_req;

typedef struct wish_rpc_request {
    wish_rpc_id_t id;
    
    /**
     *  context used for sending replies, is a: 
     *   - peer            in wish_app_protocol_rpc
     *   - remote host     in wish-core intercore RPC
     *   - wsid            in wish-core service RPC
     */
    void* response_context;
    
    rpc_client_req* next;
} wish_rpc_req;

typedef struct wish_rpc_client {
    char* name;
    /** context used to store wish_core_t in wish implementation */
    void* context;
    /** This is the ID that will be used in next req */
    wish_rpc_id_t next_id;
    /** Pointer to first request */
    rpc_client_req* requests;
    /** Send function for client */
    void (*send)(void* ctx, uint8_t* buffer, int buffer_len);
    /** Send function context */
    void* send_ctx;
} rpc_client;

/** This struct encapsulates a Wish RPC server op handler */
typedef struct wish_rpc_server_handler {
    /** the operation that this handler handles */
    char op[MAX_RPC_OP_LEN];
    char* doc;
    char* args;
    rpc_op_handler handler;
    struct wish_rpc_server_handler *next;
} rpc_handler;

/* If WISH_RPC_SERVER_STATIC_REQUEST_POOL is defined, you must supply the RPC server with a statically allocated buffer for storing wish_rpc_ctx structures.
 You must also initialise wish_rpc_server_t.rpc_ctx_pool_num_slots accordingly. */
//#define WISH_RPC_SERVER_STATIC_REQUEST_POOL

typedef struct wish_rpc_server {
    char name[MAX_RPC_SERVER_NAME_LEN];
    rpc_handler* handlers;
    /** Server context */
    void* context;
    /** Send function for sending data back to the client */
    rpc_server_send_cb send;    
    /** A list representing the requests that have arrived to the RPC server. Used in for example to emit 'sig' responses */
    rpc_server_req* requests;
    /** Access control implementation */
    rpc_acl_check_handler acl_check;
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    /** RPC contexts of incoming requests are stored to this pool */
    rpc_server_req* rpc_ctx_pool;
    /** The number of slots in the rpc_ctx_pool */
    int rpc_ctx_pool_num_slots;
#endif
} rpc_server;

rpc_server* wish_rpc_server_init(void* context, rpc_server_send_cb cb);

rpc_server* wish_rpc_server_init_size(void* context, rpc_server_send_cb cb, int size);

// acl_check(resource, acl, context, cb) { cb(err, allowed, permissions) }

void wish_rpc_server_set_acl(rpc_server* server, rpc_acl_check_handler acl);

void wish_rpc_server_set_name(rpc_server* server, const char* name);

void wish_rpc_server_register(rpc_server* server, rpc_handler* handler);

/**
 * Handle an RPC request to an RPC server
 * 
 * Returns 0, if the request was valid, and 1 if there was no handler to this "op" 
 * 
 * @param s the RPC server instance
 * @param rpc_ctx the RPC request context, NOTE: it must be obtained via wish_rpc_server_get_free_rpc_ctx_elem()
 * @param args the request argument BSON array
 * @return 0 for success, 1 for fail
 */
int wish_rpc_server_handle(rpc_server* server, rpc_server_req* req, const uint8_t* args);

void wish_rpc_server_end(rpc_server* server, int end);

void wish_rpc_server_end_by_ctx(rpc_server* server, void* ctx);

void wish_rpc_server_end_by_context(rpc_server* server, void* context);

void wish_rpc_server_receive(rpc_server* server, void* ctx, void* context, const bson* msg);

int wish_rpc_server_send(rpc_server_req* req, const uint8_t *response, size_t response_len);

int wish_rpc_server_emit(rpc_server_req* req, const uint8_t *response, size_t response_len);

int wish_rpc_server_error(rpc_server_req* req, const uint8_t *response, size_t response_len);

int wish_rpc_server_error_msg(rpc_server_req* req, int code, const uint8_t *msg);

rpc_server_req* wish_rpc_server_req_by_id(rpc_server* s, int id);

void wish_rpc_server_emit_broadcast(rpc_server* s, char* op, const uint8_t *response, size_t response_len);

void wish_rpc_server_delete_rpc_ctx(rpc_server_req* req);

rpc_client_req* find_request_entry(rpc_client* client, wish_rpc_id_t id);

rpc_client_req* find_passthrough_request_entry(rpc_client* client, wish_rpc_id_t id);

wish_rpc_id_t wish_rpc_client_bson(rpc_client* client, const char* op, const uint8_t *args, size_t args_len, rpc_client_callback cb, uint8_t *buffer, size_t buffer_len);

void wish_rpc_client_end_by_ctx(rpc_client* client, void* ctx);

void wish_rpc_client_end_by_id(rpc_client* client, int id);

void wish_rpc_client_set_cb_context(rpc_client* client, int id, void* ctx);

int wish_rpc_passthru_context(rpc_client* client, const bson* bs, rpc_client_callback cb, void* ctx);

int wish_rpc_passthru(rpc_client* client, bson* bs, rpc_client_callback cb);

int wish_rpc_passthru_req(rpc_server_req* server_rpc_ctx, rpc_client* client, bson* bs, rpc_client_callback cb);

int wish_rpc_client_handle_res(rpc_client *c, void *ctx, const uint8_t *data, size_t len);

rpc_server_req* wish_rpc_server_get_free_req(rpc_server *s);

void wish_rpc_server_print(rpc_server *s);

#ifdef __cplusplus
}
#endif
