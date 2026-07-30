# ReflectiveDLL
Tooling with c++


- test() function reflective loads DLL into new address, fixes base relocations, imports and execute at address of entrypoint as dllmain()
- Write Injector to self/remote copy into other process, parse exports and run test() function
