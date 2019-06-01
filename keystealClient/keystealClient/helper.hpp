//
//  helper.hpp
//  keystealClient
//
//  Created by Linus Henze on 01.06.19.
//  Copyright © 2019 Linus Henze. All rights reserved.
//

#ifndef helper_h
#define helper_h

#include <stdio.h>
#include <mach/mach.h>

mach_port_t recvPort(mach_port_t from);
int sendRequest(mach_port_t to, mach_port_t local);

#endif /* helper_h */
