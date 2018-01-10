#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "wish_rpc.h"
#include "wish_platform.h"
#include "wish_debug.h"
#include "bson.h"
#include "bson_visit.h"
#include "utlist.h"

rpc_server* rpc_server_init(void* context, rpc_server_send_fn cb) {
    return rpc_server_init_size(context, cb, 10);
}

rpc_server* rpc_server_init_size(void* context, rpc_server_send_fn cb, int size) {
    rpc_server* server = wish_platform_malloc(sizeof(rpc_server));
    
    if (server == NULL) { return NULL; }
    
    memset(server, 0, sizeof(rpc_server));
    
    server->requests = NULL;
    
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    server->rpc_ctx_pool = wish_platform_malloc(sizeof(rpc_server_req)*size);
    memset(server->rpc_ctx_pool, 0, sizeof(rpc_server_req)*size);
    server->rpc_ctx_pool_num_slots = size;
#else
    // server->rpc_ctx_pool = NULL;
    // server->rpc_ctx_pool_num_slots = 0;
#endif
    
    server->send = cb;
    server->context = context;
    
    return server;
}

void rpc_server_destroy(rpc_server* server) {
    if (server != NULL) {
        wish_platform_free(server);
    }
}

void rpc_server_set_acl(rpc_server* server, rpc_acl_check_handler acl_check) {
    server->acl_check = acl_check;
}

void rpc_server_set_name(rpc_server* server, const char* name) {
    strncpy(server->name, name, MAX_RPC_SERVER_NAME_LEN);
}

static rpc_handler* rpc_server_find_handle(rpc_server* server, const char * op) {
    rpc_handler* handler = server->handlers;
    
    while (handler != NULL) {
        if (!handler->op) { continue; }
        if (strncmp(handler->op, op, MAX_RPC_OP_LEN) == 0) {
            return handler;
        }
        handler = handler->next;
    }
    
    return NULL;
}

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
static int rpc_server_handle(rpc_server* server, rpc_server_req* req, const uint8_t* args) {
    rpc_handler* handler;

    LL_FOREACH(req->server->handlers, handler) {
        if (!req->op || !handler->op) { continue; }
        
        if (strncmp(handler->op, req->op, MAX_RPC_OP_LEN) == 0) {
            // FIXME currently reusing the op string from handler (to optimize memory usage with a few bytes)
            req->op = handler->op;

            /* Call the RPC handler. */
            handler->handler(req, args);

            return 0;
        }
    }
    
    return 1;
}

static rpc_server_req* rpc_server_req_init(rpc_server *server) {
    rpc_server_req* req = NULL;
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    if (server == NULL || server->rpc_ctx_pool_num_slots == 0 || server->rpc_ctx_pool == NULL) {
        WISHDEBUG(LOG_CRITICAL, "RPC server %s: Cannot save RPC request context!", server->name);
    } else {
        int i = 0;
        for (i = 0; i < server->rpc_ctx_pool_num_slots; i++) {
            /* A request pool slot is empty if the op_str is empty. */
            if (strnlen(server->rpc_ctx_pool[i].request_ctx.op, MAX_RPC_OP_LEN) == 0) {
                /* Found free request pool slot */
                req = &(server->rpc_ctx_pool[i]);
                LL_APPEND(server->requests, req);
                break;
            } 
        }
    }
#else
    req = wish_platform_malloc(sizeof(rpc_server_req));
    if (req) {
        memset(req, 0, sizeof(rpc_server_req));
        LL_APPEND(server->requests, req);
    }
#endif
    return req;
}

/**
 * Instantiate new request for client
 * 
 * @param c
 * @param cb
 * @return 
 */
static rpc_client_req* rpc_client_req_init(rpc_client* client, rpc_client_callback cb, void* cb_context) {
    rpc_client_req* req = wish_platform_malloc(sizeof (rpc_client_req));

    if (req == NULL) {
        WISHDEBUG(LOG_CRITICAL, "malloc fail");
        return NULL;
    } 

    memset(req, 0, sizeof (rpc_client_req));

    req->client = client;

    // ensure rpc will not send a request with reqest id 0.
    if (client->next_id == 0) { client->next_id++; }

    req->id = client->next_id++;
    req->cb = cb;
    req->cb_context = cb_context;
    if (client->requests == NULL) {
        /* list empty. Put new node as first on the list */
        client->requests = req;
    } else {
        rpc_client_req* entry = client->requests;
        while (entry->next != NULL) {
            entry = entry->next;
        }
        /* node now points to the last item on the list */
        /* Save new request at end of list */
        entry->next = req;
    }
    return req;
}

rpc_client_req* rpc_client_find_req(rpc_client* client, rpc_id id) {
    rpc_client_req* entry = client->requests;
    while (entry != NULL) {
        //WISHDEBUG(LOG_CRITICAL, "  iterating %i passthrough %i", entry->id, entry->passthru_id);
        if (entry->id == id) {
            break;
        }
        entry = entry->next;
    }
    return entry;
}

rpc_client_req* rpc_client_find_passthru_req(rpc_client *c, rpc_id id) {
    rpc_client_req* entry = c->requests;
    while (entry != NULL) {
        if (entry->passthru_id == id) {
            break;
        }
        entry = entry->next;
    }
    return entry;
}

/*
static rpc_client_req* find_request_entry_by_ctx(rpc_client *c, void* ctx) {
    rpc_client_req* entry = c->requests;
    while (entry != NULL) {
        if (entry->cb_context == ctx) {
            break;
        }
        entry = entry->next;
    }
    return entry;
}
*/

static void delete_request_entry(rpc_client *c, rpc_id id) {
    rpc_client_req* entry = c->requests;
    rpc_client_req* prev = NULL;
    
    int n = 0;
    
    while (entry != NULL) {
        n++;
        if (entry->id == id) {
            break;
        }
        prev = entry;
        entry = entry->next;
    }

    if (entry == NULL) {
        WISHDEBUG(LOG_DEBUG, "entry not found id: %i in client %p (checked %i entries) compile with DEBUG for more details.", id, c, n);
        return;
    }

    /* Entry now points to entry with said id */

    if (prev != NULL) {
        rpc_client_req* tmp = entry;
        prev->next = entry->next;
        wish_platform_free(tmp);
    } else {
        /* Special case: when our RPC entry was first in list */
        rpc_client_req* tmp = c->requests->next;
        wish_platform_free(c->requests);
        c->requests = tmp;
    }
}

rpc_client_req* rpc_client_request(rpc_client* client, bson* req, rpc_client_callback cb, void* cb_context) {
    if (cb == NULL) { WISHDEBUG(LOG_CRITICAL, "cb == NULL"); return 0; }
    
    // FIXME Do checks on req to validate its content
    
    bson_iterator it;
    
    if ( BSON_INT != bson_find(&it, req, "id") ) { 
        WISHDEBUG(LOG_CRITICAL, "There was no id field in request, bailing out");
        return NULL;
    }
    
    if (bson_iterator_int(&it) != 0) {
        WISHDEBUG(LOG_CRITICAL, "Error: rpc_client_request required id field value to be 0.");
        return NULL;
    }
    
    rpc_client_req* creq = rpc_client_req_init(client, cb, cb_context);
    
    if (creq == NULL) { return NULL; }
    
    bson_inplace_set_long(&it, creq->id);
    
    return creq;
}

void rpc_client_end_by_ctx(rpc_client *c, void* ctx) {
    //WISHDEBUG(LOG_CRITICAL, "Should cleanup, what have we here? provided ctx is %p", ctx);
    rpc_client_req* entry = c->requests;
    while (entry != NULL) {
        if (entry->cb_context == ctx) {
            //WISHDEBUG(LOG_CRITICAL, "  delete: %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);
            /* Save the pointer 'entry' to a tmp variable, because 'entry' might be deleted by 'delete_request_entry' */
            rpc_client_req* tmp = entry->next;
            delete_request_entry(c, entry->id); /* 'entry' pointer might be invalid after this! */
            entry = tmp;            /* Update loop variable */
        } else {
            //WISHDEBUG(LOG_CRITICAL, "  spare:  %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);
            entry = entry->next;    /* Update loop variable */
        }
    }
}

void rpc_client_end_by_id(rpc_client* client, int id) {
    rpc_client_req* entry = client->requests;
    
    //WISHDEBUG(LOG_CRITICAL, "  wish_rpc_client_end_by_id, %p", entry);
    
    while (entry != NULL) {
        if (entry->id == id) {
            //WISHDEBUG(LOG_CRITICAL, "  delete: %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);

            int buffer_len = 200;
            char buffer[buffer_len];

            bson bs;
            bson_init_buffer(&bs, buffer, buffer_len);
            bson_append_int(&bs, "end", entry->id);
            bson_finish(&bs);
            
            client->send(client->send_ctx, (uint8_t*) bson_data(&bs), bson_size(&bs));
            
            // FIXME wait for fin, to delete, now we just delete when sending end.
            delete_request_entry(client, entry->id);
            //break;
        } else {
            //WISHDEBUG(LOG_CRITICAL, "  spare:  %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);
        }
        entry = entry->next;
    }
}

void rpc_client_passthru_end_by_id(rpc_client* client, int id) {
    rpc_client_req* entry = client->requests;
    
    while (entry != NULL) {
        if (entry->passthru_id == id) {
            int buffer_len = 200;
            char buffer[buffer_len];

            bson bs;
            bson_init_buffer(&bs, buffer, buffer_len);
            bson_append_int(&bs, "end", entry->id);
            bson_finish(&bs);
            
            client->send(client->send_ctx, (uint8_t*) bson_data(&bs), bson_size(&bs));
            
            // FIXME wait for fin, to delete, now we just delete when sending end.
            delete_request_entry(client, entry->id);
            //break;
        } else {
            //WISHDEBUG(LOG_CRITICAL, "  spare:  %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);
        }
        entry = entry->next;
    }
}

static void rpc_passthru_cb(rpc_client_req* req, void* ctx, const uint8_t* payload, size_t payload_len) {
    bool end = false;
    
    if (req == NULL) {
        WISHDEBUG(LOG_CRITICAL, "passthru callback with null request not allowed.");
        return;
    }
    
    /* Re-write the ack/sig/err/etc. codes */
    bson_iterator it;
    bson_find_from_buffer(&it, payload, "ack");
    if (bson_iterator_type(&it) != BSON_EOO) {
        bson_inplace_set_long(&it, req->passthru_id);
        end = true;
    } else {
        /* ack not found, try sig */
        bson_find_from_buffer(&it, payload, "sig");
        if (bson_iterator_type(&it) != BSON_EOO) {
            bson_inplace_set_long(&it, req->passthru_id);
        } else {
            /* sig not found, try err */
            bson_find_from_buffer(&it, payload, "err");
            if (bson_iterator_type(&it) != BSON_EOO) {
                bson_inplace_set_long(&it, req->passthru_id);
                end = true;
            }
        }
    }
    
    /* FIXME add support for end/fin, which ever it should be */
    
    //WISHDEBUG(LOG_CRITICAL, "passthru callback switched ack(id) back: %i to %i", id, req->passthru_id);
    
    if (req->passthru_cb != NULL) {
        rpc_client_callback cb = req->passthru_cb;
        // should ctx actaully be req->passthru_ctx ?
        cb(req, ctx, payload, payload_len);
    }
    
    if (end) {
        //WISHDEBUG(LOG_CRITICAL, "END passthru cleanup");
        delete_request_entry(req->cb_context, req->id);
    } else {
        //WISHDEBUG(LOG_CRITICAL, "END passthru NOT cleaning up");
    }
}

/*
 * Called when passthrough client receives a response
 */
static void rpc_passthru_req_cb(rpc_client_req* req, void* ctx, const uint8_t* payload, size_t payload_len) {
    bool end = false;
    
    if (req == NULL) {
        WISHDEBUG(LOG_CRITICAL, "passthru callback with null request not allowed.");
        return;
    }
    
    /* Re-write the ack/sig/err/etc. codes */
    bson_iterator it;
    bson_find_from_buffer(&it, payload, "ack");
    if (bson_iterator_type(&it) != BSON_EOO) {
        bson_inplace_set_long(&it, req->passthru_id);
        end = true;
    } else {
        /* ack not found, try sig */
        bson_find_from_buffer(&it, payload, "sig");
        if (bson_iterator_type(&it) != BSON_EOO) {
            bson_inplace_set_long(&it, req->passthru_id);
        } else {
            /* sig not found, try err */
            bson_find_from_buffer(&it, payload, "err");
            if (bson_iterator_type(&it) != BSON_EOO) {
                bson_inplace_set_long(&it, req->passthru_id);
                end = true;
            }
        }
    }
    
    /* FIXME add support for end/fin, which ever it should be */
    
    rpc_client_callback cb = req->passthru_cb;
    cb(req, req->cb_context, payload, payload_len);
    
    if (end) {
        //rpc_server_delete_req(req->cb_context);
    }
}

rpc_client_req* rpc_client_passthru(rpc_client* client, const bson* bs, rpc_client_callback cb, void* ctx) {
    if(client->send == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Passthru has no send function");
        return 0;
    }
    
    rpc_client_req* req = rpc_client_req_init(client, rpc_passthru_cb, client);
    
    if (req == NULL) { return 0; }
    
    rpc_id id = req->id;
    
    int len = bson_size(bs);
    uint8_t buffer[len];
    
    memcpy(buffer, bson_data(bs), len);

    //bson_visit("passthru...", buffer);
    
    bson_iterator it;
    bson_find_from_buffer(&it, buffer, "id");
    req->passthru_id = bson_iterator_int(&it);
    req->passthru_cb = cb;
    
    //WISHDEBUG(LOG_CRITICAL, "Passthru setting cb_context to client pointer: %p", client);
    req->passthru_ctx2 = ctx;

    // FIXME: the passthrough context should probably be removed when each peer gets its own rpc_client
    req->passthru_ctx = client->send_ctx;

    bson_inplace_set_long(&it, id);
    
    //WISHDEBUG(LOG_CRITICAL, "Switched id in passthru: %i for %i", e->passthru_id, id);
    //bson_visit("Switched id in passthru:", buffer);
    
    client->send(client->send_ctx, buffer, len);
    return req;
}

rpc_client_req* rpc_server_passthru(rpc_server_req* req, rpc_client* client, bson* bs, rpc_client_callback cb) {
    if(client->send == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Passthru has no send function");
        return 0;
    }
    
    rpc_client_req* creq = rpc_client_req_init(client, rpc_passthru_req_cb, req);

    if (creq == NULL) { return NULL; }

    rpc_id id = creq->id;
    
    int len = bson_size(bs);
    uint8_t buffer[len];
    
    memcpy(buffer, bson_data(bs), len);

    bson_iterator it;
    bson_find_from_buffer(&it, buffer, "id");
    creq->passthru_id = bson_iterator_int(&it);
    creq->passthru_cb = cb;
    
    // FIXME: the passthrough context should probably be removed when each peer gets its own rpc_client
    creq->passthru_ctx = client->send_ctx;

    bson_inplace_set_long(&it, id);
    
    client->send(client->send_ctx, buffer, len);
    return creq;
}


void rpc_client_passthru_end(rpc_client* client, int id) {
    // FIXME does this actually end the passthru request?
    rpc_client_end_by_id(client, id);
}

void rpc_server_delete_req(rpc_server_req* req) {
    if (req->op == NULL) {
        WISHDEBUG(LOG_CRITICAL, "delete null req, is not a good idea.");
        return;
    }
    
    //WISHDEBUG(LOG_CRITICAL, "Searching for something to delete.. %p %p %p", req, req->server, req->server->requests);
    rpc_server_req* elm = NULL;
    rpc_server_req* tmp = NULL;
    
    LL_FOREACH_SAFE(req->server->requests, elm, tmp) {
        if (elm == req) {
            //WISHDEBUG(LOG_CRITICAL, "Deleting rpc ctx");
           
            LL_DELETE(req->server->requests, elm);
            
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
            req->op = NULL;
#else
            wish_platform_free(req);
#endif
            break;
        }
    }
}

static void acl_decision(rpc_server_req* req, bool allowed) {
    if (!allowed) {
        rpc_server_error_msg(req, 200, "Permission denied.");
        return;
    }
    
    if (rpc_server_handle(req->server, req, req->args)) {
        WISHDEBUG(LOG_DEBUG, "RPC server fail: wish_core_app_rpc_func");
    }
}

void rpc_server_receive(rpc_server* server, void* ctx, void* context, const bson* msg) {
    // TODO: refactor to use the bson directly, not like this.
    const char* data = bson_data(msg);
        
    int end = 0;
    
    bson_iterator it;
    bson_iterator_from_buffer(&it, data);
    
    if (bson_find_fieldpath_value("op", &it) != BSON_STRING) {
        bson_iterator_from_buffer(&it, data);
        if ( bson_find_fieldpath_value("end", &it) != BSON_INT ) {
            WISHDEBUG(LOG_CRITICAL, "rpc_server_receive: %s (no op or end)", server->name);
            bson_visit("rpc_server_receive: no 'op' or 'end':", data);
            return;
        }
        
        end = bson_iterator_int(&it);
        rpc_server_end(server, end);
        return;
    }
    
    const char* op = bson_iterator_string(&it);
    
    //WISHDEBUG(LOG_CRITICAL, "op %s from app %s", op, app->service_name);

    bson_iterator_from_buffer(&it, data);

    const uint8_t* args = NULL;
    
    if (bson_find_fieldpath_value("args", &it) != BSON_ARRAY) {
        int empty_args_len = 32;
        uint8_t empty_args[empty_args_len];
        bson bs;
        bson_init_buffer(&bs, empty_args, empty_args_len);
        bson_append_start_array(&bs, "args");
        bson_append_finish_array(&bs);
        bson_finish(&bs);
        args = bson_data(&bs);
    } else {
        args = bson_iterator_value(&it);
    }

    bson_iterator_from_buffer(&it, data);

    int32_t id = 0;
    
    if (bson_find_fieldpath_value("id", &it) == BSON_INT) {
        id = bson_iterator_int(&it);
    }
    
    rpc_server_req *req = rpc_server_req_init(server);
    
    if (req == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_rpc_server_receive: out of memory (%s)", server->name);
        
        rpc_server_req err_req;
        err_req.server = server;
        err_req.send_context = &err_req;
        err_req.id = id;
        err_req.ctx = ctx;
        err_req.context = context;
        
        char err_str[256];
        
        wish_platform_sprintf(err_str, "rpc-server request memory full: %s", server->name);
        
        rpc_server_error_msg(&err_req, 63, err_str);
        return;
    } else if ( strnlen(op, MAX_RPC_OP_LEN) >= MAX_RPC_OP_LEN ) {
        WISHDEBUG(LOG_CRITICAL, "wish_rpc_server_receive(%s): too long op string.", server->name);
        
        rpc_server_req err_req;
        err_req.server = server;
        err_req.send_context = &err_req;
        err_req.id = id;
        err_req.ctx = ctx;
        err_req.context = context;
        
        rpc_server_error_msg(&err_req, 63, "Op string is too long.");
        return;
    } else {
        rpc_handler* handler = rpc_server_find_handle(server, op);

        req->server = server;
        req->send_context = req;
        req->id = id;
        req->ctx = ctx;
        req->context = context;
        req->args = args;
        
        if (handler == NULL) { rpc_server_error_msg(req, 8, "Command not found or permission denied."); return; }
        
        req->op = handler->op;

        if (server->acl_check) {
            //WISHDEBUG(LOG_CRITICAL, "VIA ACL RPC server %s does not contain op: %s.", server->name, req->op);
            server->acl_check(req, op, "call", NULL, acl_decision);
        } else {
            if (rpc_server_handle(server, req, args)) {
                WISHDEBUG(LOG_CRITICAL, "RPC server %s does not contain op: %s.", server->name, req->op);
                rpc_server_error_msg(req, 8, "Command not found or permission denied.");
            }
        }
    }
}

static int rpc_server_send2(rpc_server_req* req, const uint8_t* response, size_t response_len, const char* type, bool delete) {

    if (req->id == 0 && delete) { rpc_server_delete_req(req); return 0; }
    
    int buffer_len = response_len + 512;
    char buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);

    if (response == NULL) {
        // send ack without any data
        bson_append_int(&bs, type, req->id);
        bson_finish(&bs);
    } else {
        // expect bson document with data property
        bson_iterator it;
        bson_find_from_buffer(&it, response, "data");
        
        bson_type bt = bson_iterator_type(&it);
        
        if (bt != BSON_EOO) {
            bson_append_element(&bs, "data", &it);
        } else {
            WISHDEBUG(LOG_CRITICAL, "Unsupported bson type %i in wish_rpc_server_send2", bt);
        }

        bson_append_int(&bs, type, req->id);
        bson_finish(&bs);
    }
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in wish_rpc_server_send");
        return 1;
    }
    
    req->server->send(req->send_context, &bs);
    
    if (delete) { rpc_server_delete_req(req); }
    
    return 0;
}

/* { data: bson_element ack: req_id } */
int rpc_server_send(rpc_server_req* req, const uint8_t* response, size_t response_len) {
    return rpc_server_send2(req, response, response_len, "ack", true);
}

/* { data: bson_element sig: req_id } */
int rpc_server_emit(rpc_server_req* req, const uint8_t* response, size_t response_len) {
    return rpc_server_send2(req, response, response_len, "sig", false);
}

/* { data: bson_element err: req_id } */
int rpc_server_error(rpc_server_req* req, const uint8_t* response, size_t response_len) {
    return rpc_server_send2(req, response, response_len, "err", true);
}

/* { data: { code: errno, msg: errstr } err: req_id } */
int rpc_server_error_msg(rpc_server_req* req, int code, const uint8_t *msg) {
    //WISHDEBUG(LOG_CRITICAL, "Generating rpc_error: %i %s", code, msg);
    if (strnlen(msg, WISH_RPC_ERR_MSG_MAX_LEN) == WISH_RPC_ERR_MSG_MAX_LEN) {
        WISHDEBUG(LOG_CRITICAL, "Error message too long in wish_rpc_server_error");
        return 1;
    }
    
    int buffer_len = WISH_RPC_ERR_MSG_MAX_LEN + 128;
    char buffer[buffer_len];
    memset(buffer, 0, buffer_len);

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    bson_append_int(&bs, "code", code);
    bson_append_string(&bs, "msg", msg);
    bson_append_finish_object(&bs);
    bson_append_int(&bs, "err", req->id);
    bson_finish(&bs);
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in wish_rpc_server_error");
        return 1;
    }
    
    req->server->send(req->send_context, &bs);
    rpc_server_delete_req(req);
    return 0;
}

/**
 * Request is done from the server side
 */
/* { data: bson_element fin: req_id } */
int rpc_server_fin(rpc_server_req* req) {
    return rpc_server_send2(req, NULL, 0, "fin", true);
}

void rpc_server_emit_broadcast(rpc_server* server, char* op, const uint8_t *data, size_t data_len) {
    /* Traverse the list of requests in the given server, and for each request where op_str equals given op, emit the data */
    rpc_server_req* req;
    
    LL_FOREACH(server->requests, req) {
        if (!req->op) { continue; }
        if (strncmp(req->op, op, MAX_RPC_OP_LEN) == 0) {
            rpc_server_emit(req, data, data_len);
        }
    }
}

int rpc_client_receive(rpc_client* c, void* ctx, const uint8_t* data, size_t data_len) {
    
    bool sig = false;
    bool fin = false;
    bool err = false;
    int retval = 0;
    rpc_id id = -1;
    
    bson_iterator it;
    
    if (bson_find_from_buffer(&it, data, "ack") == BSON_INT) {
        id = bson_iterator_int(&it);
    } else {
        if (bson_find_from_buffer(&it, data, "sig") == BSON_INT) {
            id = bson_iterator_int(&it);
            //WISHDEBUG(LOG_DEBUG, "Sig id %i", id);
            /* Do not remove the callback if we get "sig" instead of
             * ack" */
            sig = true;
        } else if (bson_find_from_buffer(&it, data, "err") == BSON_INT) {
            id = bson_iterator_int(&it);
            //bson_visit("Error return for RPC", data);
            err = true;
        } else if (bson_find_from_buffer(&it, data, "fin") == BSON_INT) {
            id = bson_iterator_int(&it);
            //WISHDEBUG(LOG_CRITICAL, "Fin message for RPC id %d", id);
            fin = true;
        } else {
            bson_visit("RPC error: no ack, sig or err, message follows:", data);
            return retval;
        }
    }

    /* If we get here, then we have an ack or err to an id */
    rpc_client_req* rpc_entry = rpc_client_find_req(c, id);
    
    if (rpc_entry == NULL) {
        WISHDEBUG(LOG_CRITICAL, "No RPC entry for id %d %s", id, c->name);
        bson_visit("No RPC entry for id", data);
        retval = 1;
    } else {
        
        if (fin) {
            rpc_entry->fin = true;
            rpc_entry->cb(rpc_entry, ctx, data, data_len);
            delete_request_entry(c, id);
            return retval;
        }
        
        rpc_entry->err = err;
        rpc_entry->sig = sig;
        rpc_entry->fin = fin;
        
        if (rpc_entry->cb != NULL) {
            rpc_entry->cb(rpc_entry, ctx, data, data_len);
        } else {
            WISHDEBUG(LOG_CRITICAL, "RPC callback is null! (id %d)", id);
        }
        
        if (sig == false) { delete_request_entry(c, id); }
    }
    return retval;
}

/** Server: Add a RPC handler */
void rpc_server_register(rpc_server* server, rpc_handler* handler) {
    /* Find correct place to add the new handler new_h */
    rpc_handler* h = server->handlers;

    if (h == NULL) {
        WISHDEBUG(LOG_DEBUG, "The RPC server %s does not have any handlers, adding first entry", server->name);
        server->handlers = handler;
    } else {
        while (h->next != NULL) {
            h = h->next;
        }
        h->next = handler;
    }
}

void rpc_server_print(rpc_server* server) {
    WISHDEBUG(LOG_CRITICAL, "RPC server %s:", server->name);
    // Count the active number of requests
    int c = 0;
    
    rpc_server_req* elm = NULL;
    
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    int i;
    
    for (i = 0; i < server->rpc_ctx_pool_num_slots; i++) {
        // A request pool slot is empty if the op_str is empty.
        if (strnlen(server->rpc_ctx_pool[i].op, MAX_RPC_OP_LEN) != 0) {
            c++;
            WISHDEBUG(LOG_CRITICAL, "  %s", server->rpc_ctx_pool[i].op);
        }
    }
#else
    LL_FOREACH(server->requests, elm) {
        WISHDEBUG(LOG_CRITICAL, "  %s", elm->op);
        c++;
    }
#endif    
    
    WISHDEBUG(LOG_CRITICAL, "  requests registered %i", c);
}

rpc_server_req* rpc_server_req_by_id(rpc_server* server, int id) {
    rpc_server_req* req;
    LL_FOREACH(server->requests, req) {

        if (req->id == id) {
            return req;
            break;
        }
    }

    return NULL;
}

void rpc_server_end(rpc_server *server, int id) {
    rpc_server_req* req = NULL;
    rpc_server_req* elm;
    
    LL_FOREACH(server->requests, elm) {
        if (elm->id == id) {
            req = elm;
            break;
        }
    }    
    
    if (req != NULL) {
        /* Call the end handler if it is set */
        if(req->end != NULL) { req->end(req); }
        
        rpc_server_fin(req);

        /* Delete the request context */
        //rpc_server_delete_req(req);
    } else {
        WISHDEBUG(LOG_DEBUG, "RPC server %s has no request with id: %i.", server->name, id);
    }
}

void rpc_server_end_by_ctx(rpc_server* server, void* ctx) {
    rpc_server_req* elm;
    rpc_server_req* tmp;
    
    LL_FOREACH_SAFE(server->requests, elm, tmp) {
        if (elm->ctx == ctx) {
            rpc_server_req* req = elm;
            
            if(req->end != NULL) { req->end(req); }
            rpc_server_delete_req(req);
        }
    }
}


void rpc_server_end_by_context(rpc_server* server, void* context) {
    rpc_server_req* elm;
    rpc_server_req* tmp;
    
    LL_FOREACH_SAFE(server->requests, elm ,tmp) {

        if (elm->context == context) {
            rpc_server_req* req = elm;
            
            /* Call the end handler if it is set */
            if(req->end != NULL) { req->end(req); }

            /* Delete the request context */
            rpc_server_delete_req(req);
            break;
        }
    }
}


