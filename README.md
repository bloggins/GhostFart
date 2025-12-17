Code taken from https://github.com/mansk1es/GhostFart

Added AES encrypt & wrote loader

VS compile > Build Dependancies > Build Customizations > check masm > OK

Righ-click on stubs.asm > Properties > Item Type > Microsoft Macro Assembler.

From original Github

Unhooking is performed via indirect syscalls.

Leveraging NTAPI to grab NTDLL for unhooking without triggering "PspCreateProcessNotifyRoutine". We've been using this one for a while but I figured some people aren't familiar with how NTAPIs themselves can make a difference at times.
Basically this variant doesn't trigger a process creation event, because the "process" we generate doesn't have really any information, no threads, no environment, any major thing, it's not even an .exe file (it is a PE). BUT! ntdll is clean-ly loaded, and the new process also doesn't show in Task Manager as well.
