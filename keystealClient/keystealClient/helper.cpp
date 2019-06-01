//
//  helper.cpp
//  keystealClient
//
//  Created by Linus Henze on 01.06.19.
//  Copyright © 2019 Linus Henze. All rights reserved.
//

#include "helper.hpp"

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


int sendRequest(mach_port_t to, mach_port_t local) {
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
    } msg;
    
    msg.header.msgh_remote_port = to;
    msg.header.msgh_local_port = local;
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size = sizeof(msg);
    
    msg.body.msgh_descriptor_count = 0;
    
    kern_return_t kr = mach_msg_send(&msg.header);
    if (kr != KERN_SUCCESS) {
        return 1;
    }
    
    return 0;
}
