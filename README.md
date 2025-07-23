## ICMPv6-Filter-Module

###  Module Purpose
This Linux kernel module uses Netfilter to inspect incoming IPv6 packets:
- Filters ICMPv6 packets by **type** (e.g., Echo Request = 128)
- Matches packets from a specific **IPv6 source address**
- Optionally **drops** or just logs matching packets
- Offers runtime configuration via a `/proc` file

---

##  Core Components Explained

### 1. **Includes & Definitions**
```c
#include <linux/module.h>       // For module macros
#include <linux/netfilter.h>    // Netfilter base
#include <linux/netfilter_ipv6.h> // IPv6 Netfilter
#include <linux/ipv6.h>         // IPv6 headers
#include <linux/icmpv6.h>       // ICMPv6 header
#include <linux/proc_fs.h>      // /proc file system
#include <linux/uaccess.h>      // Copy from user space
```
These headers pull in the kernel APIs you'll need.

---

### 2. **Global Settings**
```c
#define PROC_NAME "icmpv6_filter"
#define MAX_INPUT 128
```
- This sets up your `/proc/icmpv6_filter` file
- Input buffer for commands from userspace is limited to 128 bytes

---

### 3. **Filter State Variables**
```c
static struct in6_addr match_ip = IN6ADDR_ANY_INIT;
static int icmp_type = 128;
static bool drop = false;
```
- `match_ip`: IPv6 address to match. Default: any address
- `icmp_type`: Default is 128 (Echo Request)
- `drop`: `false` means log, `true` means drop

---

### 4. **Packet Inspection Hook**
```c
static unsigned int filter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
```
This function is called on every packet before it's routed:
- Extracts IPv6 and ICMPv6 headers
- Compares packet’s type and source IP against module's settings
- Logs and accepts or drops based on current `drop` state

---

### 5. **/proc Write Handler**
```c
static ssize_t proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
```
- Reads configuration string from userspace, like:
  ```
  type=135 ip=fe80::1 drop=1
  ```
- Updates the module's internal parameters using `sscanf()`
- Converts IP string into binary format with `in6_pton()`

---

### 6. **/proc File Ops Struct**
```c
static struct proc_ops proc_file_ops = {
    .proc_write = proc_write,
};
```
This ties your write handler to the proc file’s behavior.

---

### 7. **Module Initialization**
```c
static int __init filter_init(void)
```
- Registers the Netfilter hook
- Creates the `/proc` file
- Loads your module and prints a kernel log

---

### 8. **Module Cleanup**
```c
static void __exit filter_exit(void)
```
- Removes the proc entry and Netfilter hook when the module is unloaded

---

##  Runtime Interaction
Once loaded:
```bash
echo "type=135 ip=fe80::1 drop=1" | sudo tee /proc/icmpv6_filter
```
 This updates the module to **drop** incoming **Neighbor Solicitation** (type 135) messages from **fe80::1**.

Check your logs:
```bash
dmesg | grep ICMPv6
```


