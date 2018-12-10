# Simpleator

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

Simpleator ("Simple-ator") is an innovative Windows-centric x64 user-mode application emulator that leverages several new features that were added in Windows 10 Spring Update (1803), also called "Redstone 4", with additional improvements that were made in Windows 10 October Update (1809), aka "Redstone 5".

Namely, Simpleator relies on:
* The Hyper-V Platform API (WHVP) which now allows compatible applications to leverage the Hyper-V hypervisor in order to create and manage "Exo" Partitions, providing a similar API as KVM on Linux.
* Changes to the Memory Manager API which resulted in the creation of the VirtualAlloc2 and MapViewOfFile3 APIs that allow constraining alignment, minimum, and maximum address ranges, without custom hooks or hacks.
* Improvements to WHVP in 1809, specifically the ability to partially unmap guest physical address (GPA) ranges.

It is meant as a Proof-of-Concept on how simpler and faster sandboxed detonation environments could be built, as well as even more resource-limited containers that could run serverless workloads (AWS Lambdas / Azure Functions) without requiring a guest operating system.

## Building

Simpleator can be built with Visual Studio 2017 and the latest Windows SDK (1809). Note that older SDKs cannot be used, as they do not support the newer WHVP definitions, and that Simpleator itself only supports 64-bit Windows 10 systems running builds 17763 or above (Redstone 5 / 1809).

## Screenshots

The main Monitor Window which traces the system calls, shown here displaying the console output from the test guest application:

![Monitor](https://raw.githubusercontent.com/ionescu007/Simpleator/master/monitor.PNG)

The Register Window, which can be used when there's an assertion/issue with the emulator (the UI thread will freeze, hence the "not responding" message):

![Registers](https://raw.githubusercontent.com/ionescu007/Simpleator/master/registers.PNG)

And finally, if enabling the `FLG_SHOW_LDR_SNAPS` flag in the PEB, the Debug Window shows calls to `DbgPrint` from the loader (otherwise, any other DbgPrint calls would show up regardless):

![Debug](https://raw.githubusercontent.com/ionescu007/Simpleator/master/debug.PNG)

## Motivation

tbd tbd add links

Developers have been writing, and leveraging, emulation technologies for decades, so why write yet another emulator?

First, the introduction of an actual virtualization API in the heart of Windows is an under-publicized dramatic (in a positive way) shift to the previous closed nature of the Hyper-V Platform. While there were undocumented APIs and IOCTLs through the Virtualization Infrastructure Device (VID) library, a supported and stable Win32 layer is a welcomed improvement. Already, QEMU now supports using WHVP for its acceleration, and VirtualBox 6.0 will likely ship with this support as well (it is already implemented in the repository). Only VMWare stands alone and defiant. On this topic, learning how to leverage this new API isn't necessarily an easy topic, so I wanted to learn -- and share with others -- how these new interfaces work.

Second, when looking at emulation technologies, there are usually three modern driving forces for its use:
* The ability to emulate full operating systems, for purposes of testing, development, education, and compatibility or accessibility.
* The ability to over-subscribe a machine, such as for providing cloud/container-type services
* The ability to safely 'detonate' potentially malicious code and study its behavior

My main interest was to look at the third bullet -- which so far has been achieved with full system emulation, with some custom implementations that use over-subscription models, but still bringing lots of complexity -- a case in point being most Antivirus Emulators, such as the one implemented in Windows Defender (see some great research [here] and [here]). Furthermore, researchers familiar with Qilin have probably already seen the multitude of simple Python bindings that easily build upon it in order to quickly 'spin-up' a Windows process using an over-subscription model by leveraging QEMU as a full system emulator but yet without a primary OS image.

I decided to pursue another avenue -- a sort of 'user-mode Windows' implementation, where the only binaries mapped in the guest address space would be the host's OS loader (Ntdll.dll) and the target binary, and where a 256 GB address space would be provided that would have native 1:1 access between guest virtual mappings and host virtual mappings, in a 'sandboxed' process (NOTE: I have not yet implemented the AppContainer-based sandboxing). As long as the emulator would provide the basic kernel-constructed data structures for the loader and system DLLs, the host could run at native speeds, with only privileged Ring transitions causing exits.

Then, for simplicity, a System Call Provider intercepts the system calls that are being made by the guest VM, and can operate in one of three ways:

* Forward the call natively to the host operating system
* Adjust certain parameters and/or modify the behavior of the call in order to satisfy the needs of the emulation environment (including perhaps blocking or not implementing the call)
* Similar to the point above, constrain the call from a security point of view, such that the guest code is not attempting to operate on system-call-accessible state that belongs to the host

Depending on where the needs lie between performance, complexity, compatibility and security, less than 500 lines of code are needed to implement enough of bullets 1 and 2 above to get a simple test application to load, display a "Hello World" message, and exit, with lots of potential security issues in handling its system calls. A doubling of the codebase could probably realistically mitigate most of the security issues in the system calls (minus actual vulnerabilities in the host OS kernel -- which a sandbox could mitigate against).

But even at 1000 lines of code, since all of the system calls are ultimately natively sent to the operating system, Simpleator behaves more like a 'seccomp' implementation on top of a cgroup on Linux, rather than the much more complex emulators that we see today.

Finally, it's worth pointing out that there's renewed interest in the cloud computing/containerization space to minimize the resources needed for running workloads such as Amazon Lambdas or Azure Functions, which are serverless pieces of code that run in containers, which still require spinning up an entire guest operating system. With a stricter control of the security boundaries that Simpleator provides, one could imagine the ability to run the JVM or .NET Core as a dedicated application without requiring a full guest OS.

## Basic Design

tbd tbd

There are 3 main interesting parts (to me) about how Simpleator achieves a unique guest execution environment that makes it much simpler to run Windows applications:

* The creation of a PEB and TEB with the same kind of data that the kernel's `MiCreatePebOrTeb` functions would set up, but with specific flags to make it easier to run under the guest environment, including
    1) Running as a secure process todo: Flag
    2) Running as a protected process todo: Flag
    3) Disabling IFEO todo: Flag

* Creating a 1:1 mapping between guest and host addresses, and leveraging the new "address requirements" features to lock down allocations to that range. Note that at the moment, Simpleator maps the authentic `KUSER_SHARED_DATA` region at `0x7FFE0000` which means that the passage of time is 'seen' by the guest VM thanks to the updating of the `SystemTime` and `InterruptTime` fields that are kept up to date by the host. Isolating this region would require a periodic timer to emulate updating this value.

* Mapping the authentic `Ntdll.dll` image and leveraging the host OS system calls to natively execute most of the loading process, providing access to `INT 2E`, `SYSCALL` and `INT 2C` ring transitions.
 


Additionally, from a modularity basis, Simpleator is composed of three binaries:

* `Simpleator.exe` which implements the Debug Monitor. This component is responsible for displaying the UI for the Monitor, Debug, and Register windows, hosting a named pipe which allows the emulator to communicate with it, and loading the emulator with an appropriate environment (today, this means setting up the 256 GB address space reservation, in the future, this would also mean the sandbox).
* `Provider.dll` which implements the System Call Provider for Windows 10 1809 (RS5) and Windows 10 1903 (19H1), the current builds supported.
* `Emulator.exe` which implements the actual WHVP-accelerated emulator code. It is mainly responsible for communicating with the Debug Monitor over the pipe, handling the ring transition code to talk to and from the System Call Provider, and doing the initial address space setup and PE loading of the `Ntdll.dll` loader library and the target application binary.



## Testing

First, you must install the Windows Hypervisor Platform, which also requires Hyper-V to be installed and enabled. You can do so either by using the following command-line:

```Dism /Online /Enable-Feature /FeatureName:HypervisorPlatform```

Or by launching the GUI as below:

```OptionalFeatures.exe```

And then checking the "Hyper-V" and "Windows Hypervisor Platform" checkboxes, as seen in the screenshot below.

![Optional Features](https://raw.githubusercontent.com/ionescu007/Simpleator/master/OptionalFeatures.png)

You must have administrative rights for usage of any of these commands.

Obviously, please make sure that your hardware supports Hardware Virtualization Technology (such as Intel VT-x).

## References

If you would like to know more about my research or work, I invite you check out my blog at http://www.alex-ionescu.com as well as my training & consulting company, Winsider Seminars & Solutions Inc., at http://www.windows-internals.com.

tbd tbd

## Caveats and Limitations

Simpleator is designed to minimize code size and complexity -- this does come at a cost of robustness and most importantly, security. For example, in the current implementation, `NtCreateFile`, `NtOpenFile` and `NtWriteFile` are fully passed through to the host OS kernel, meaning that a 'malicious' payload could overwrite any files on disk that the host emulator process has access to, since there is no additional sandboxing around the host.

Furthermore, note that only the _strict minimum number of system calls_ were implemented to get the `Testapp.exe` application to launch, print its text, and exit. Running a more complex application such as `Cmd.exe` will require significantly more work, especially as certain APIs expect a connection to CSRSS to be made over LPC and for particular data to be returned back. Currently, Simpleator pretends that it is a Secure VTL-1 Protected Process, which limits significantly what some of the guest APIs attempt to do, and therefore, certain calls outright crash (such as, for example, some of those around locale). 

More complex emulation and modification of the guest's address space would be required to unblock such API usage.

***Simpleator does not do much error checking, validation, and exception handling. It is not robust software designed for production use, but rather a reference code base***.

## License

```
Copyright 2018 Alex Ionescu. All rights reserved. 

Redistribution and use in source and binary forms, with or without modification, are permitted provided
that the following conditions are met: 
1. Redistributions of source code must retain the above copyright notice, this list of conditions and
   the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
   and the following disclaimer in the documentation and/or other materials provided with the 
   distribution. 

THIS SOFTWARE IS PROVIDED BY ALEX IONESCU ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ALEX IONESCU
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the authors and
should not be interpreted as representing official policies, either expressed or implied, of Alex Ionescu.
```
