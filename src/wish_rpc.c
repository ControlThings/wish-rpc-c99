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

rpc_server* wish_rpc_server_init(void* context, rpc_server_send_cb cb) {
    return wish_rpc_server_init_size(context, cb, 10);
}

rpc_server* wish_rpc_server_init_size(void* context, rpc_server_send_cb cb, int size) {
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

void wish_rpc_server_destroy(rpc_server* server) {
    if (server != NULL) {
        wish_platform_free(server);
    }
}

void wish_rpc_server_set_acl(rpc_server* server, rpc_acl_check_handler acl_check) {
    server->acl_check = acl_check;
}

void wish_rpc_server_set_name(rpc_server* server, const char* name) {
    strncpy(server->name, name, MAX_RPC_SERVER_NAME_LEN);
}

/**
 * Instantiate new request for client
 * 
 * @param c
 * @param cb
 * @return 
 */
static wish_rpc_id_t create_request_entry(rpc_client *c, rpc_client_callback cb) {
    rpc_client_req* req = wish_platform_malloc(sizeof (rpc_client_req));

    if (req == NULL) {
        WISHDEBUG(LOG_CRITICAL, "malloc fail");
        return 0;
    } 

    memset(req, 0, sizeof (rpc_client_req));

    req->client = c;

    // ensure rpc will not send a request with reqest id 0.
    if (c->next_id == 0) { c->next_id++; }

    req->id = c->next_id++;
    req->cb = cb;
    if (c->requests == NULL) {
        /* list empty. Put new node as first on the list */
        c->requests = req;
    } else {
        rpc_client_req* entry = c->requests;
        while (entry->next != NULL) {
            entry = entry->next;
        }
        /* node now points to the last item on the list */
        /* Save new request at end of list */
        entry->next = req;
    }
    return req->id;
}

rpc_client_req* find_request_entry(rpc_client* client, wish_rpc_id_t id) {
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

rpc_client_req* find_passthrough_request_entry(rpc_client *c, wish_rpc_id_t id) {
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

static void delete_request_entry(rpc_client *c, wish_rpc_id_t id) {
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

#ifdef DEBUG        
        entry = c->requests;

        int n = 0;

        while (entry != NULL) {
            n++;
            WISHDEBUG(LOG_CRITICAL, "  checked: %i", entry->id);
            if (entry->id == id) {
                break;
            }
            entry = entry->next;
        }
#endif
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

wish_rpc_id_t wish_rpc_client_bson(rpc_client* c, const char* op, 
        const uint8_t* args_array, size_t args_len, rpc_client_callback cb,
        uint8_t* buffer, size_t buffer_len) {
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_string(&bs, "op", op);
    
    if (args_len == 0 || args_array == NULL) {
        bson_append_start_array(&bs, "args");
        bson_append_finish_array(&bs);
    } else {
        bson_iterator it;
        bson_find_from_buffer(&it, args_array, "args");
        if(bson_iterator_type(&it) != BSON_ARRAY) {
            // args property must be array
            WISHDEBUG(LOG_CRITICAL, "Dumping request! Args property must be array!");
            return 0;
        }
        bson_append_element(&bs, "args", &it);
    }
    
    wish_rpc_id_t id = 0;
    
    if (cb != NULL) {
        id = create_request_entry(c, cb);
        bson_append_int(&bs, "id", id);
    }
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "wish_rpc_client_bson error writing bson");
        return 0;
    }
    
    bson_finish(&bs);

    
    // show active requests
    
    WISHDEBUG(LOG_CRITICAL, "rpc_client %p, looking for id: %d", c, id);
    
    rpc_client_req* entry = c->list_head;
    while (entry != NULL) {
        WISHDEBUG(LOG_CRITICAL, "  entry: %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);
        entry = entry->next;
    }
    
    //bson_visit("wish_app_core: BSON Dump", bs.data);
    
    return id;
}

void wish_rpc_client_end_by_ctx(rpc_client *c, void* ctx) {
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

void wish_rpc_client_end_by_id(rpc_client *c, int id) {
    rpc_client_req* entry = c->requests;
    
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
            
            c->send(c->send_ctx, (uint8_t*) bson_data(&bs), bson_size(&bs));
            
            // FIXME wait for fin, to delete, now we just delete when sending end.
            delete_request_entry(c, entry->id);
            //break;
        } else {
            //WISHDEBUG(LOG_CRITICAL, "  spare:  %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);
        }
        entry = entry->next;
    }
}

void wish_rpc_client_set_cb_context(rpc_client* client, int id, void* ctx) {
    rpc_client_req* entry = client->requests;
    
    while (entry != NULL) {
        if (entry->id == id) {
            entry->cb_context = ctx;
            WISHDEBUG(LOG_CRITICAL, "  wish_rpc_client_set_cb_context done, %p", ctx);
            return;
        }
        entry = entry->next;
    }
    
    /* Failed setting cb context */
    WISHDEBUG(LOG_CRITICAL, "Failed setting cb context!");
}

static void wish_rpc_passthru_cb(rpc_client_req* req, void* ctx, const uint8_t* payload, size_t payload_len) {
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
static void wish_rpc_passthru_req_cb(rpc_client_req* req, void* ctx, const uint8_t* payload, size_t payload_len) {
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
        wish_rpc_server_delete_rpc_ctx(req->cb_context);
    }
}

int wish_rpc_passthru(rpc_client* client, bson* bs, rpc_client_callback cb) {
    return wish_rpc_passthru_context(client, bs, cb, NULL);
}

int wish_rpc_passthru_context(rpc_client* client, const bson* bs, rpc_client_callback cb, void* ctx) {
    if(client->send == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Passthru has no send function");
        return 0;
    }
    
    wish_rpc_id_t id = create_request_entry(client, wish_rpc_passthru_cb);
    rpc_client_req* e = find_request_entry(client, id);
    
    int len = bson_size(bs);
    uint8_t buffer[len];
    
    memcpy(buffer, bson_data(bs), len);

    //bson_visit("passthru...", buffer);
    
    bson_iterator it;
    bson_find_from_buffer(&it, buffer, "id");
    e->passthru_id = bson_iterator_int(&it);
    e->passthru_cb = cb;
    
    //WISHDEBUG(LOG_CRITICAL, "Passthru setting cb_context to client pointer: %p", client);
    e->cb_context = client;
    e->passthru_ctx2 = ctx;

    // FIXME: the passthrough context should probably be removed when each peer gets its own rpc_client
    e->passthru_ctx = client->send_ctx;

    bson_inplace_set_long(&it, id);
    
    //WISHDEBUG(LOG_CRITICAL, "Switched id in passthru: %i for %i", e->passthru_id, id);
    //bson_visit("Switched id in passthru:", buffer);
    
    client->send(client->send_ctx, buffer, len);
    return id;
}

int wish_rpc_passthru_req(rpc_server_req* req, rpc_client* client, bson* bs, rpc_client_callback cb) {
    if(client->send == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Passthru has no send function");
        return 0;
    }
    
    wish_rpc_id_t id = create_request_entry(client, wish_rpc_passthru_req_cb);
    rpc_client_req* e = find_request_entry(client, id);
    
    int len = bson_size(bs);
    uint8_t buffer[len];
    
    memcpy(buffer, bson_data(bs), len);

    bson_iterator it;
    bson_find_from_buffer(&it, buffer, "id");
    e->passthru_id = bson_iterator_int(&it);
    e->passthru_cb = cb;
    
    e->cb_context = req;
    
    // FIXME: the passthrough context should probably be removed when each peer gets its own rpc_client
    e->passthru_ctx = client->send_ctx;

    bson_inplace_set_long(&it, id);
    
    client->send(client->send_ctx, buffer, len);
    return id;
}


void wish_rpc_passthru_end(rpc_client* client, int id) {
    wish_rpc_client_end_by_id(client, id);
}

void wish_rpc_server_delete_rpc_ctx(rpc_server_req* req) {
    //WISHDEBUG(LOG_CRITICAL, "Searching for something to delete.. %p %p %p", req, req->server, req->server->requests);
    rpc_server_req* elm = NULL;
    rpc_server_req* tmp = NULL;
    
    LL_FOREACH_SAFE(req->server->requests, elm, tmp) {
        if (elm == req) {
            //WISHDEBUG(LOG_CRITICAL, "Deleting rpc ctx");
           
            LL_DELETE(req->server->requests, elm);
            
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
            memset(req->op, 0, MAX_RPC_OP_LEN);
#else
            wish_platform_free(req);
#endif
            break;
        }
    }
}

static void acl_decision(rpc_server_req* req, bool allowed) {
    if (!allowed) {
        wish_rpc_server_error_msg(req, 200, "Permission denied.");
        return;
    }
    
    if (wish_rpc_server_handle(req->server, req, req->args)) {
        WISHDEBUG(LOG_DEBUG, "RPC server fail: wish_core_app_rpc_func");
    }
}

void wish_rpc_server_receive(rpc_server* server, void* ctx, void* context, const bson* msg) {
    // TODO: refactor to use the bson directly, not like this.
    const char* data = bson_data(msg);
        
    int end = 0;
    
    bson_iterator it;
    bson_iterator_from_buffer(&it, data);
    
    if (bson_find_fieldpath_value("op", &it) != BSON_STRING) {
        bson_iterator_from_buffer(&it, data);
        if ( bson_find_fieldpath_value("end", &it) != BSON_INT ) {
            bson_visit("There was no 'op' or 'end':", data);
            return;
        } else {
            wish_rpc_server_end(server, end);
            return;
        }
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
    } else {
        args = bson_iterator_value(&it);
    }

    bson_iterator_from_buffer(&it, data);

    int32_t id = 0;
    
    if (bson_find_fieldpath_value("id", &it) == BSON_INT) {
        id = bson_iterator_int(&it);
    }
    
    rpc_server_req *request = wish_rpc_server_get_free_req(server);
    
    if (request == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_rpc_server_receive: out of memory (%s)", server->name);
        
        rpc_server_req err_req;
        err_req.server = server;
        err_req.send_context = &err_req;
        err_req.id = id;
        err_req.ctx = ctx;
        err_req.context = context;
        
        char err_str[256];
        
        wish_platform_sprintf(err_str, "rpc-server request memory full: %s", server->name);
        
        wish_rpc_server_error_msg(&err_req, 63, err_str);
        return;
    } else if ( strnlen(op, MAX_RPC_OP_LEN) >= MAX_RPC_OP_LEN ) {
        WISHDEBUG(LOG_CRITICAL, "wish_rpc_server_receive(%s): too long op string.", server->name);
        
        rpc_server_req err_req;
        err_req.server = server;
        err_req.send_context = &err_req;
        err_req.id = id;
        err_req.ctx = ctx;
        err_req.context = context;
        
        wish_rpc_server_error_msg(&err_req, 63, "Op string is too long.");
        return;
    } else {
        rpc_server_req* req = request;
        req->server = server;
        req->send_context = req;
        strncpy(req->op, op, MAX_RPC_OP_LEN);
        req->id = id;
        req->ctx = ctx;
        req->context = context;
        req->args = args;

        if (server->acl_check) {
            server->acl_check(req, op, "call", NULL, acl_decision);
        } else {
            if (wish_rpc_server_handle(server, req, args)) {
                WISHDEBUG(LOG_CRITICAL, "RPC server %s does not contain op: %s.", server->name, req->op);
                wish_rpc_server_error_msg(req, 8, "Command not found or permission denied.");
            }
        }
    }
}

static int wish_rpc_server_send2(rpc_server_req* req, const uint8_t* response, size_t response_len, const char* type, bool delete) {

    if (req->id == 0 && delete) {
        // we should not send any response, just delete the request
        wish_rpc_server_delete_rpc_ctx(req);
        return 0;
    }
    
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
        
        // FIXME check type under iterator is valid
        if (bt == BSON_STRING) {
            bson_append_string(&bs, "data", bson_iterator_string(&it));
        } else if (bt == BSON_BOOL) {
            bson_append_bool(&bs, "data", bson_iterator_bool(&it));
        } else if (bt == BSON_NULL) {
            bson_append_null(&bs, "data");
        } else if (bt == BSON_INT) {
            bson_append_int(&bs, "data", bson_iterator_int(&it));
        } else if (bt == BSON_DOUBLE) {
            bson_append_double(&bs, "data", bson_iterator_double(&it));
        } else if (bt == BSON_BINDATA) {
            bson_append_binary(&bs, "data", bson_iterator_bin_data(&it), bson_iterator_bin_len(&it));
        } else if (bt == BSON_OBJECT) {
            bson_append_element(&bs, "data", &it);
        } else if (bt == BSON_ARRAY) {
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
    
    if (delete) { wish_rpc_server_delete_rpc_ctx(req); }
    
    return 0;
}

/* { data: bson_element ack: req_id } */
int wish_rpc_server_send(rpc_server_req* req, const uint8_t* response, size_t response_len) {
    return wish_rpc_server_send2(req, response, response_len, "ack", true);
}

/* { data: bson_element sig: req_id } */
int wish_rpc_server_emit(rpc_server_req* req, const uint8_t* response, size_t response_len) {
    return wish_rpc_server_send2(req, response, response_len, "sig", false);
}

/* { data: bson_element err: req_id } */
int wish_rpc_server_error(rpc_server_req* req, const uint8_t* response, size_t response_len) {
    return wish_rpc_server_send2(req, response, response_len, "err", true);
}

/* { data: { code: errno, msg: errstr } err: req_id } */
int wish_rpc_server_error_msg(rpc_server_req* req, int code, const uint8_t *msg) {
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
    wish_rpc_server_delete_rpc_ctx(req);
    return 0;
}

void wish_rpc_server_emit_broadcast(rpc_server* server, char* op, const uint8_t *data, size_t data_len) {
    /* Traverse the list of requests in the given server, and for each request where op_str equals given op, emit the data */
    rpc_server_req* req;
    LL_FOREACH(server->requests, req) {

        if (strncmp(req->op, op, MAX_RPC_OP_LEN) == 0) {
            wish_rpc_server_emit(req, data, data_len);
        }
    }
}

int wish_rpc_client_handle_res(rpc_client* c, void* ctx, const uint8_t* data, size_t data_len) {
    
    bool sig = false;
    bool fin = false;
    bool err = false;
    int retval = 0;
    wish_rpc_id_t id = -1;
    
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
    rpc_client_req* rpc_entry = find_request_entry(c, id);
    
    if (rpc_entry == NULL) {
        WISHDEBUG(LOG_CRITICAL, "No RPC entry for id %d", id);
        bson_visit("No RPC entry for id", data);
        retval = 1;
    } else {
        
        if (fin) {
            delete_request_entry(c, id);
            return retval;
        }
        
        rpc_entry->err = err;
        
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
void wish_rpc_server_register(rpc_server *s, rpc_handler* handler) {
    /* Find correct place to add the new handler new_h */
    rpc_handler* h = s->handlers;

    if (h == NULL) {
        WISHDEBUG(LOG_DEBUG, "The RPC server %s does not have any handlers, adding first entry", s->name);
        s->handlers = handler;
    } else {
        while (h->next != NULL) {
            h = h->next;
        }
        h->next = handler;
    }
}

rpc_server_req* wish_rpc_server_get_free_req(rpc_server *s) {
    rpc_server_req* req = NULL;
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    if (s == NULL || s->rpc_ctx_pool_num_slots == 0 || s->rpc_ctx_pool == NULL) {
        WISHDEBUG(LOG_CRITICAL, "RPC server %s: Cannot save RPC request context!", s->name);
    } else {
        int i = 0;
        for (i = 0; i < s->rpc_ctx_pool_num_slots; i++) {
            /* A request pool slot is empty if the op_str is empty. */
            if (strnlen(s->rpc_ctx_pool[i].request_ctx.op, MAX_RPC_OP_LEN) == 0) {
                /* Found free request pool slot */
                req = &(s->rpc_ctx_pool[i]);
                LL_APPEND(s->requests, req);
                break;
            } 
        }
    }
#else
    req = wish_platform_malloc(sizeof(rpc_server_req));
    if (req) {
        memset(req, 0, sizeof(rpc_server_req));
        LL_APPEND(s->requests, req);
    }
#endif
    return req;
}

void wish_rpc_server_print(rpc_server *s) {
    WISHDEBUG(LOG_CRITICAL, "RPC server %s:", s->name);
    // Count the active number of requests
    int c = 0;
    
    rpc_server_req* elm = NULL;
    
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    int i;
    
    for (i = 0; i < s->rpc_ctx_pool_num_slots; i++) {
        // A request pool slot is empty if the op_str is empty.
        if (strnlen(s->rpc_ctx_pool[i].op, MAX_RPC_OP_LEN) != 0) {
            c++;
            WISHDEBUG(LOG_CRITICAL, "  %s", s->rpc_ctx_pool[i].op);
        }
    }
#else
    LL_FOREACH(s->requests, elm) {
        WISHDEBUG(LOG_CRITICAL, "  %s", elm->op);
        c++;
    }
#endif    
    
    WISHDEBUG(LOG_CRITICAL, "  requests registered %i", c);
}

int wish_rpc_server_handle(rpc_server* s, rpc_server_req* req, const uint8_t *args) {
    rpc_handler *h = req->server->handlers;
    // Searching for RPC handler op rpc_ctx->op_str
    if (h == NULL) {
        WISHDEBUG(LOG_CRITICAL, "RPC server %s does not have handlers. Req id: %d.", s->name, req->id);
        bson_visit("RPC server msg", args);
    } else {
        do {
            if (strncmp(h->op, req->op, MAX_RPC_OP_LEN) == 0) {
                // Found handler

                /* Call the RPC handler. */
                h->handler(req, args);
                
                return 0;
            }
            h = h->next;
        } while (h != NULL);
    }
    return 1;
}

rpc_server_req* wish_rpc_server_req_by_id(rpc_server *s, int id) {
    rpc_server_req* req;
    LL_FOREACH(s->requests, req) {

        if (req->id == id) {
            return req;
            break;
        }
    }

    return NULL;
}

void wish_rpc_server_end(rpc_server *s, int id) {
    rpc_server_req *req = NULL;
    /* Traverse the list of requests in the given server, and for each request where op_str equals given op, emit the data */
    rpc_server_req* elm;
    LL_FOREACH(s->requests, elm) {

        if (elm->id == id) {
            req = elm;
            break;
        }
    }    
    
    // Searching for RPC handler op rpc_ctx->op_str
    if (req != NULL) {
        /* Call the end handler if it is set */
        if(req->end != NULL) { req->end(req); }

        /* Delete the request context */
        wish_rpc_server_delete_rpc_ctx(req);
        
        //WISHDEBUG(LOG_CRITICAL, "RPC server %s cleaned up request with id: %i.", s->server_name, id);
    } else {
        WISHDEBUG(LOG_DEBUG, "RPC server %s has no request with id: %i.", s->name, id);
    }
}

void wish_rpc_server_end_by_ctx(rpc_server* server, void* ctx) {
    rpc_server_req* elm;
    rpc_server_req* tmp;
    
    LL_FOREACH_SAFE(server->requests, elm, tmp) {
        if (elm->ctx == ctx) {
            rpc_server_req* req = elm;
            
            if(req->end != NULL) { req->end(req); }
            wish_rpc_server_delete_rpc_ctx(req);
        }
    }
}


void wish_rpc_server_end_by_context(rpc_server* server, void* context) {
    rpc_server_req* elm;
    rpc_server_req* tmp;
    
    LL_FOREACH_SAFE(server->requests, elm ,tmp) {

        if (elm->context == context) {
            rpc_server_req* req = elm;
            
            /* Call the end handler if it is set */
            if(req->end != NULL) { req->end(req); }

            /* Delete the request context */
            wish_rpc_server_delete_rpc_ctx(req);
            break;
        }
    }
}


