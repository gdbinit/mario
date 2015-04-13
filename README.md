Mario - The kernel component to fix rootpipe

Copyright (c) fG!, 2015. All rights reserved.  
reverser@put.as - https://reverse.put.as

A TrustedBSD kernel driver to inject a dynamic library or a __RESTRICT segment into specific processes.  
This kernel extension will intercept new processes before they are executed and modifies their headers so a dynamic library is loaded on startup.

Tested with Mavericks 10.9.5.  
Should work with previous versions with minor or no adaptations (TrustedBSD hook prototype changed between Mavericks and Yosemite).

Don't forget to send a message to Apple thanking for keeping you vulnerable ;-
)  

Have fun,  
fG!
