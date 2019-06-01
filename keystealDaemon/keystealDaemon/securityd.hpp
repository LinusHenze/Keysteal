//
//  securityd.hpp
//  keystealDaemon
//
//  Created by Linus Henze on 21.01.19.
//  Copyright © 2019 Linus Henze. All rights reserved.
//

#ifndef securityd_hpp
#define securityd_hpp

#include <stdio.h>
#include "ucsp.hpp"
#include <mach/mach.h>

extern "C" kern_return_t
bootstrap_look_up(mach_port_t  bootstrap_port,
                  char*        service_name,
                  mach_port_t* service_port);

extern mach_port_t gServerPort;

CSSM_RETURN securityd_setup();
CSSM_RETURN securityd_setup_withport(mach_port_t port);
CSSM_RETURN securityd_mksession_withport(mach_port_t replyPort, mach_port_t task);
CSSM_RETURN securityd_setup_hosting(mach_port_t port);
CSSM_RETURN securityd_free_port(mach_port_t port);

mach_port_t recvPort(mach_port_t from);
mach_port_t recvPortWithReply(mach_port_t from, mach_port_t *client);
int sendPort(mach_port_t to, mach_port_t port);
int sendPortMake(mach_port_t to, mach_port_t port);
int sendPortReceiveRight(mach_port_t to, mach_port_t port);

#endif /* securityd_hpp */
