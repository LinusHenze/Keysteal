# KeySteal
KeySteal is a macOS <= 10.13.3 Keychain exploit that allows you to access passwords inside the Keychain without a user prompt.  
KeySteal consists of two parts:
1. KeySteal Daemon: This is a daemon that exploits securityd to get a session that is allowed to access the Keychain without a password prompt.
2. KeySteal Client: This is a library that can be injected into Apps. It will automatically apply a patch that forces the Security Framework to use the session of our keysteal daemon.

# Building and Running
1. Open the KeySteal Xcode Project
2. Build the keystealDaemon and keystealClient
3. Open the directory which contains the built daemon and client (right cick on keystealDaemon -> Open in Finder)
4. Run dump-keychain.sh

# TODO
Add a link to my talk about this vulnerability at [Objective by the Sea](https://objectivebythesea.com/v2/)

# License
For most files, see LICENSE.txt.  
The following files were taken (or generated) from [Security-58286.220.15](https://opensource.apple.com/source/Security/Security-58286.220.15/) and are under the Apple Public Source License:
* handletypes.h
* ss_types.h
* ucsp_types.h
* ucsp.hpp
* ucspUser.cpp

A copy of the Apple Public Source License can be found [here](http://www.opensource.apple.com/apsl/).
