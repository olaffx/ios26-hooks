# ios26-bootstrap
Some iOS (iOS 26.0–26.1) bootstraps.

**WARNING**

This will **NOT** work on a real iPhone, if you want to execute the code fully you need to run it in a virtualized iPhone (vphone-aio)


**Functions that will work on a real iPhone:**

printf()
malloc()
NSString
NSBundle

**Functions that will work on a virtualized iPhone:**

printf()
malloc()
NSString
NSBundle
syscall()
ptrace()
sandbox_extension_*
MSHookFunction
IORegistry
posix_spawn hook
