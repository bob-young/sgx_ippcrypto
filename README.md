# sgx_ippcrypto
a demo for using ipp in sgx

note:
using ippcp outside enclave you should link .a lib
using ippcp inside enclave you should link .so lib
so you shoud config your makefile with differet link to ippcp

i don't know why,maybe a bug
i`ll report to intel later

------------------------
Purpose of SampleEnclave
------------------------
The project demonstrates several fundamental usages of Intel(R) Software Guard 
Extensions (SGX) SDK:
- Initializing and destroying an enclave
- Creating ECALLs or OCALLs
- Calling trusted libraries inside the enclave

------------------------------------
How to Build/Execute the Sample Code
------------------------------------
1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:
    a. Hardware Mode, Debug build:
        $ make SGX_MODE=HW SGX_DEBUG=1
    b. Hardware Mode, Pre-release build:
        $ make SGX_MODE=HW SGX_PRERELEASE=1
    c. Hardware Mode, Release build:
        $ make SGX_MODE=HW
    d. Simulation Mode, Debug build:
        $ make SGX_DEBUG=1
    e. Simulation Mode, Pre-release build:
        $ make SGX_PRERELEASE=1
    f. Simulation Mode, Release build:
        $ make
3. Execute the binary directly:
    $ ./app

