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

typedef int32_t rpc_id;

typedef struct wish_rpc_server rpc_server;
typedef struct wish_rpc_context rpc_server_req;

typedef struct wish_rpc_client rpc_client;
typedef struct wish_rpc_entry rpc_client_req;

#define MAX_RPC_OP_LEN 48
#define MAX_RPC_SERVER_NAME_LEN 16
/* This defines the maximum length of an RPC error message */
#define WISH_RPC_ERR_MSG_MAX_LEN 256

typedef void (*rpc_server_send_fn)(rpc_server_req* req, const bson* bs);

typedef void (*rpc_client_callback)(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len);

typedef void (*rpc_op_handler)(rpc_server_req* req, const uint8_t* args);

/**
 * Request context for wish_rpc_server
 */
struct wish_rpc_context {
    /** Pointer to RPC Server */
    rpc_server* server;
    /** 
     * Operator 
     * 
     * The operator string is used to select the handler registered in the server
     */
    const char* op;
    /**
     * Arguments for RPC command
     */
    const char* args;
    /** Request ID */
    int id;
    /** Server unique id */
    int sid;
    /** 
     * The originating wish context of the message, used in core rpc
     * server, send_op_handler(). 
     */
    void* ctx;
    /** Pointer to the wanted context structure  */
    void* context; 
    /** Send function context passed as the first argument to the send function */
    void* send_context;
    /** If non-null this callback is called when a request is terminated */
    void (*end)(struct wish_rpc_context *req);
    /** list pointer */
    struct wish_rpc_context* next;
};

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

struct wish_rpc_entry {
    rpc_client* client;
    rpc_id id;
    rpc_client_callback cb;
    void* cb_context;
    rpc_client_callback passthru_cb;
    int passthru_id;
    /** used for storing peer pointer in passthrough. This field should probably should be removed when introducing separate rpc_clients for each peer */
    void* passthru_ctx;
    /** used for storing Mist pointer in nodejs addon */
    void* passthru_ctx2; 
    rpc_client_req* next;
    bool err;
    bool sig;
    bool fin;
    /** Clean-up function which is called when this request is removed from client's list of outstanding requests */
    void (*cleanup)(rpc_client_req* req);
};

struct wish_rpc_request {
    rpc_id id;
    
    /**
     *  context used for sending replies, is a: 
     *   - peer            in wish_app_protocol_rpc
     *   - remote host     in wish-core intercore RPC
     *   - wsid            in wish-core service RPC
     */
    void* response_context;
    
    rpc_client_req* next;
};

struct wish_rpc_client {
    char* name;
    /** context used to store wish_core_t in wish implementation */
    void* context;
    /** This is the ID that will be used in next req */
    rpc_id next_id;
    /** Pointer to first request */
    rpc_client_req* requests;
    /** Send function for client */
    void (*send)(void* ctx, uint8_t* buffer, int buffer_len);
    /** Send function context */
    void* send_ctx;
};

typedef struct wish_rpc_server_handler rpc_handler;

/** This struct encapsulates a Wish RPC server op handler */
struct wish_rpc_server_handler {
    /** the operation that this handler handles */
    char* op;
    char* doc;
    char* args;
    rpc_op_handler handler;
    rpc_handler *next;
};

/* If WISH_RPC_SERVER_STATIC_REQUEST_POOL is defined, you must supply the RPC server with a statically allocated buffer for storing wish_rpc_ctx structures.
 You must also initialise wish_rpc_server_t.rpc_ctx_pool_num_slots accordingly. */
//#define WISH_RPC_SERVER_STATIC_REQUEST_POOL

struct wish_rpc_server {
    char name[MAX_RPC_SERVER_NAME_LEN];
    rpc_handler* handlers;
    /** unique request id */
    int rid;
    /** Server context */
    void* context;
    /** Send function for sending data back to the client */
    rpc_server_send_fn send;    
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
};

/* Server functions */

rpc_server* rpc_server_init(void* context, rpc_server_send_fn cb);

rpc_server* rpc_server_init_size(void* context, rpc_server_send_fn cb, int size);

void rpc_server_destroy(rpc_server* server);

// acl_check(resource, acl, context, cb) { cb(err, allowed, permissions) }

void rpc_server_set_acl(rpc_server* server, rpc_acl_check_handler acl);

void rpc_server_set_name(rpc_server* server, const char* name);

void rpc_server_register(rpc_server* server, rpc_handler* handler);

void rpc_server_end(rpc_server* server, int end);

void rpc_server_end_by_ctx(rpc_server* server, void* ctx);

void rpc_server_end_by_context(rpc_server* server, void* context);

void rpc_server_receive(rpc_server* server, void* ctx, void* context, const bson* msg);

int rpc_server_send(rpc_server_req* req, const uint8_t *response, size_t response_len);

int rpc_server_emit(rpc_server_req* req, const uint8_t *response, size_t response_len);

int rpc_server_error(rpc_server_req* req, const uint8_t *response, size_t response_len);

int rpc_server_error_msg(rpc_server_req* req, int code, const uint8_t *msg);

int rpc_server_fin(rpc_server_req* req);

rpc_server_req* rpc_server_req_by_id(rpc_server* server, int id);

rpc_server_req* rpc_server_req_by_sid(rpc_server* server, int sid);

void rpc_server_emit_broadcast(rpc_server* server, char* op, const uint8_t *response, size_t response_len);

void rpc_server_delete_req(rpc_server_req* req);

rpc_client_req* rpc_server_passthru(rpc_server_req* server_rpc_ctx, rpc_client* client, bson* bs, rpc_client_callback cb);

void rpc_server_print(rpc_server* server);

/* Client functions */

rpc_client_req* rpc_client_request(rpc_client* client, bson* req, rpc_client_callback cb, void* cb_context);

rpc_client_req* rpc_client_find_req(rpc_client* client, rpc_id id);

rpc_client_req* rpc_client_find_passthru_req(rpc_client* client, rpc_id id);

void rpc_client_end_by_ctx(rpc_client* client, void* ctx);

void rpc_client_end_by_id(rpc_client* client, int id);

void rpc_client_passthru_end_by_id(rpc_client* client, int id);

rpc_client_req* rpc_client_passthru(rpc_client* client, const bson* bs, rpc_client_callback cb, void* ctx);

int rpc_client_receive(rpc_client *c, void *ctx, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
