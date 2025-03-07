### Vulnerability List:

- Vulnerability Name: Intentional Kernel Vulnerability Injection via kpwn module
- Description:
    - A user with administrative privileges can load the `kpwn` kernel module into a running Linux kernel.
    - Once loaded, the `kpwn` module creates a device `/dev/kpwn` that exposes various `ioctl` commands.
    - These `ioctl` commands are designed to simulate kernel vulnerabilities for research and testing purposes.
    - An attacker, if they gain access to a system where the `kpwn` module is loaded, can interact with the `/dev/kpwn` device.
    - By sending specific `ioctl` commands, the attacker can trigger intentionally introduced vulnerabilities, such as arbitrary kernel memory read/write, kernel memory corruption, and RIP control.
    - For example, the `ARB_WRITE` ioctl allows writing arbitrary data to arbitrary kernel addresses, and `RIP_CONTROL` ioctl allows hijacking control flow.
- Impact:
    - If an attacker successfully exploits these intentionally injected vulnerabilities, they can achieve full kernel control.
    - This can lead to complete system compromise, including data theft, malware installation, and denial of service, bypassing all kernel security mechanisms.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The `kpwn` module is designed to inject vulnerabilities for research purposes, so no mitigations are implemented within the module itself.
    - The README files contain disclaimers stating that this is not an officially supported Google product and is intended for research purposes.
- Missing Mitigations:
    - **Stronger warnings and documentation:** The project should prominently display warnings in all relevant README files (project root, `kpwn` module directory, `kernel-image-runner` documentation) that clearly state the `kpwn` module is for research and testing only and MUST NOT be used in production or live kernel environments. This should be more than just a disclaimer, but a clear and upfront warning.
    - **Runtime warning in the kpwn module:** The `kpwn` module itself could include a runtime check (e.g., checking for a specific kernel configuration or environment variable) and issue a kernel log warning message upon loading if it detects it's not in a designated testing environment. This would provide an active warning to users loading the module in unintended environments.
- Preconditions:
    - The attacker needs access to a system where a user has already loaded the `kpwn` kernel module.
    - Loading the `kpwn` kernel module requires root or administrator privileges. A user with these privileges must have executed commands to load the module (e.g., `insmod kpwn.ko`).
    - The kernel must be running and the `/dev/kpwn` device must exist.
- Source Code Analysis:
    - **`third_party/kernel-modules/kpwn/kpwn.c`**: This file contains the source code for the `kpwn` kernel module.
    - The module registers a character device `/dev/kpwn` and implements the `ioctl` interface.
    - **`kpwn_ioctl` function**: This function in `kpwn.c` handles the `ioctl` commands.
    - **`enum kpwn_cmd`**:  This enum defines various commands like `ALLOC_BUFFER`, `KFREE`, `KASLR_LEAK`, `SYM_ADDR`, `WIN_TARGET`, `PRINTK`, `ARB_READ`, `ARB_WRITE`, `RIP_CONTROL`. Each of these commands implements a simulated vulnerability or exposes kernel internals.
    - **`ARB_WRITE` command (case `ARB_WRITE` in `kpwn_ioctl`)**: This command takes a user-provided kernel address (`msg->kernel_addr`), data (`msg->data`), and length (`msg->length`) and directly copies user data to the specified kernel address using `copy_from_user` and `memcpy`. This allows arbitrary kernel memory write, a critical vulnerability.
    ```c
    case ARB_WRITE:
        if (!msg || !msg->data)
            return INVALID_MSG;
        if (msg->length > MAX_MESSAGE_LENGTH)
            return INVALID_LENGTH;
        if (!msg->kernel_addr)
            return INVALID_ADDRESS;

        if (copy_from_user(ubuffer, msg->data, msg->length))
            return COPY_FROM_USER_FAILED;

        memcpy((void *)msg->kernel_addr, ubuffer, msg->length); // <--- Arbitrary kernel write here

        break;
    ```
    - **`RIP_CONTROL` command (case `RIP_CONTROL` in `kpwn_ioctl`)**: This command allows controlling the instruction pointer (RIP). It takes register values from user-space and sets CPU registers accordingly before executing `jmp r15`, `call r15`, or `ret`. This gives full RIP control, enabling arbitrary code execution in the kernel.
    ```c
    case RIP_CONTROL: {
        rip_control_args rip_args;
        if (copy_from_user(&rip_args, ubuffer, sizeof(rip_control_args)))
            return COPY_FROM_USER_FAILED;

        printk(KERN_INFO "kpwn: rip_control: action=0x%x, rsp=0x%lx, value@rsp=0x%lx, regs_to_set=0x%x, rip=0x%lx\n",
               rip_args.action, rip_args.rsp, rip_args.rsp ? *(uint64_t *)rip_args.rsp : 0, rip_args.regs_to_set, rip_args.rip);

        ret = do_rip_control(&rip_args); // <--- RIP control here
        if (ret == SUCCESS)
            printk(KERN_INFO "kpwn: kpwn: rip_control, after asm\n");
        return ret;
    }
    ```
- Security Test Case:
    1. **Prerequisites:**
        - Ensure a Linux kernel environment is set up.
        - Compile the `kpwn` kernel module: Navigate to `/code/kernel-image-runner` and run `./compile_custom_modules.sh ubuntu 5.4.0-26.30 kpwn` (or similar, choosing a supported distro and release). This will create `kpwn.ko` in `releases/ubuntu/5.4.0-26.30/custom_modules/`.
        - Compile the `test/kpwn_test.c` user-space test program: Navigate to `/code/kernel-image-runner/test` and run `gcc -static -o kpwn_test kpwn_test.c`. This will create `kpwn_test` binary.
    2. **Load the kpwn module:** As root, load the `kpwn` module into the kernel: `sudo insmod /code/kernel-image-runner/releases/ubuntu/5.4.0-26.30/custom_modules/kpwn.ko`
    3. **Run the test program (ARB_WRITE test):** Execute the compiled `kpwn_test` program as root to trigger the `ARB_WRITE` ioctl. For example, run: `sudo /code/kernel-image-runner/test/kpwn_test arb_write`. This test in `kpwn_test.c` attempts to overwrite the `core_pattern` kernel variable.
    4. **Observe the impact:** After running the test, check the output of `cat /proc/sys/kernel/core_pattern`. If the `ARB_WRITE` vulnerability is successfully triggered, the output of `core_pattern` will be changed to the new value set by the `kpwn_test` program (e.g., `|/tmp/run_as_root`). This demonstrates arbitrary kernel memory write.
    5. **Run the test program (RIP_CONTROL test):** Execute the compiled `kpwn_test` program as root to trigger the `RIP_CONTROL` ioctl. For example, run: `sudo /code/kernel-image-runner/test/kpwn_test rip_control`. This test in `kpwn_test.c` attempts to call the `win_target` function via `RIP_CONTROL`.
    6. **Observe the impact:** Check the kernel logs (e.g., using `dmesg | grep "YOU WON"`). If the `RIP_CONTROL` vulnerability is successfully triggered, you will see the "!!! YOU WON !!!" message in the kernel logs, indicating successful RIP control and arbitrary code execution.
    7. **Unload the module:** Unload the `kpwn` module to remove the vulnerability: `sudo rmmod kpwn`.

This test case demonstrates how an attacker can leverage the intentionally injected vulnerabilities in the `kpwn` module to perform arbitrary kernel memory write and gain RIP control, leading to full system compromise.