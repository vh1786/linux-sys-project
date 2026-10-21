# linux-sys: typed Ada bindings to Linux confinement and networking

*Project document, 21 October 2026. "linux-sys" is a working name (crate
`linux_sys`), to be checked before publication.*

> **Status of every claim in this document.**
> - **Measured** (21 October 2026): Linux 7.1.5 x86-64, its kernel headers
>   (`linux-libc-dev` 7.1.5), GNAT 13.3.0, and the Alire index. The
>   commands are in Appendix A.
> - **Read in the man pages**: landlock_create_ruleset(2),
>   landlock_restrict_self(2), seccomp(2), seccomp_unotify(2), packet(7),
>   socket(7), netlink(7), rtnetlink(7), sd_notify(3).
> - **[to confirm]**: details the man pages did not settle when asked
>   (the netlink dump flags and message header layout, the sd_notify and
>   socket-activation environment protocol), and anything about kernels or
>   architectures not measured. M0 reads them from the kernel and systemd
>   sources, and nothing is built on such a claim before.

---

## 1. Summary

linux-sys gives Ada programs **typed, total and tested** access to the
Linux interfaces a hardened network service needs, and that no Ada
library binds today:

| family | interfaces |
|---|---|
| **confinement** | Landlock (file system and network rules), seccomp-bpf (system call filters), `no_new_privs`, capabilities (effective, permitted, inheritable, ambient, bounding), securebits |
| **packet access** | `AF_PACKET` sockets, interface binding, promiscuous membership, classic BPF socket filters |
| **routing and neighbours** | rtnetlink: links, addresses, routes, neighbours, as dumps and as events |
| **memory and files** | `memfd_create` with seals |
| **service manager** | the `sd_notify` protocol (readiness, watchdog, status), socket activation, without linking libsystemd |

Three principles shape it:

1. **Typed**: rights, flags and actions are Ada enumerations and sets,
   never bare integers. A Landlock ruleset is built from `Access_Set`, a
   seccomp filter from a list of rules, never from hand-written BPF.
2. **Total and explicit**: no exception escapes; every call answers with
   a result that names the `errno` as an enumeration. **Best-effort is
   reported, never silent**: when the running kernel does not support a
   right asked for, the result says which rights were dropped.
3. **Constants checked against the kernel**: every number the library
   uses (syscall numbers, flag values, structure sizes and offsets) is
   generated from the kernel headers and checked by a C probe in CI. A
   wrong constant in this layer costs a privilege silently; that is the
   one defect this project exists to remove.

---

## 2. The problem

### 2.1 What a hardened service does on Linux

A service that reads hostile input confines itself: it drops the
capabilities it does not need, sets `no_new_privs`, restricts its file
system and network reach with Landlock, filters its system calls with
seccomp, and runs under a service manager that it tells when it is ready
and that it pings so a hung process is restarted. A network observer also
opens `AF_PACKET` sockets with a BPF filter, and reads routes and
neighbours from rtnetlink.

### 2.2 What Ada has today (measured in the Alire index)

| crate | covers |
|---|---|
| `florist`, `florist_blady` | POSIX.5: processes, files, signals |
| `epoll`, `inotify`, `evdev`, `socketcan`, `libgpiod`, `libsimpleio`, `linux_hal` | one Linux interface each |
| `spoon` | `posix_spawn` |
| `bbs_embed_linux`, `muntsos_*` | embedded boards |

**Nothing for Landlock, seccomp, capabilities, netlink, `AF_PACKET`,
memfd seals or the systemd protocols.** Every Ada project that needs them
writes its own `pragma Import` of `syscall`, its own constants copied from
a header, and its own structure layouts. Each one is a place where a typo
in a flag value widens a sandbox and nothing says so.

### 2.3 The failure modes this library is built against

| failure | what happens | what refuses it here |
|---|---|---|
| a flag value copied wrong from a header | a Landlock right or a seccomp action means something else; the sandbox is wider than written | constants generated from headers, checked by a C probe in CI (§6) |
| a structure layout copied wrong (`landlock_path_beneath_attr` is packed; `sock_fprog` has padding) | the kernel reads garbage, or refuses with `EINVAL` | sizes and offsets checked by the same probe |
| a right the running kernel does not know, asked anyway | `EINVAL`: the program either fails to start or skips confinement entirely | the ABI is queried first, unknown rights masked, and **the dropped rights returned** to the caller |
| a seccomp filter that forgets to check the architecture | a 32-bit system call bypasses the filter **[to confirm the exact mechanism in seccomp(2)]** | the filter builder always emits the architecture check first; proved |
| a BPF jump out of range or a program too long | the kernel refuses it, or the filter does something else | the builder proves every jump target in range and the length bounded |
| a confinement applied after a thread was started | the earlier thread is not confined **[to confirm per mechanism]** | the API documents and checks the order: confine before starting tasks, or use the thread-synchronising flag where one exists |
| a variadic C function imported with the plain C convention | wrong arguments on some ABIs | `Convention => C_Variadic_1` for `syscall` (measured to work on GNAT 13), or a C shim |

---

## 3. Goals and non-goals

### Goals

1. **Landlock**: query the ABI, build a ruleset from typed access sets
   (file system and network), add path-beneath and port rules, restrict
   self, and report what the running kernel could not enforce.
2. **seccomp**: an allow-list or deny-list DSL compiled to classic BPF by
   a proved builder; the architecture check first; actions as an
   enumeration (allow, errno, trap, log, kill process, kill thread, user
   notification **[to confirm the list against seccomp(2)]**); loading
   with or without thread synchronisation.
3. **Privileges**: `no_new_privs`; capability sets read and written;
   dropping from the bounding set; ambient capabilities; securebits.
4. **`AF_PACKET`**: open (raw or cooked), bind to an interface by index,
   join promiscuous mode by membership rather than by an interface flag,
   attach a classic BPF filter, receive with the link-layer address.
5. **Classic BPF**: the same proved builder for socket filters, with a
   small library of common filters (EtherType, VLAN, UDP port).
6. **rtnetlink**: requests built and responses parsed by proved code:
   links, addresses, routes and neighbours as dumps, plus multicast
   groups for change events.
7. **memfd**: create, write, seal (shrink, grow, write, seal), and pass
   the descriptor.
8. **Service manager**: readiness, status text, watchdog pings and the
   watchdog interval, socket activation (inherited descriptors and their
   names), all as the protocol over a datagram socket, with no dependency
   on libsystemd.
9. **Tests that run unprivileged**: every family testable inside a user
   and network namespace (measured: `unshare -rn` gives the full
   capability set inside, unprivileged).

### Non-goals

- A general POSIX binding (florist exists).
- eBPF (`bpf(2)` maps and programs): a different, much larger interface.
- cgroups, namespaces management beyond what the tests need, mount APIs.
  Possible later families, not in the first release.
- Portability to other kernels. Linux only, x86-64 and aarch64 first.

---

## 4. Architecture

```
  ┌────────────────────────────── user program ──────────────────────────────┐
  │   Linux_Sys.Landlock   .Seccomp   .Caps   .Packet   .Netlink   .Memfd   │
  │   .Service (sd_notify, activation)          .BPF (proved builder)        │
  └───────────────┬───────────────────────────────────────▲──────────────────┘
                  │ typed calls, total results            │ proved encoders/decoders
  ┌───────────────┴──────────── Linux_Sys.Raw ────────────┴──────────────────┐
  │  syscall numbers, flags, structure layouts -- GENERATED from headers     │
  │  one Import of `syscall` (C_Variadic_1); socket calls through GNAT.Sockets│
  │  or libc                                                                  │
  └───────────────┬──────────────────────────────────────────────────────────┘
                  │
  ┌───────────────┴──── generator + probe (build time, CI) ──────────────────┐
  │  reads <linux/*.h>, emits Linux_Sys.Raw.Constants_<arch>; a C program    │
  │  prints every value, size and offset; CI compares both                   │
  └──────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Two layers

- **`Linux_Sys.Raw`**: thin, one-to-one with the kernel. Generated
  constants, record types with representation clauses whose size and
  offsets are checked against the C probe, and imports. Nothing here is
  meant for users, but it is public for those who need it.
- **The typed layer**: one package per family. Here the rules live:
  enumerations, sets, results, best-effort reporting, ordering checks.

### 4.2 Results, never exceptions

```ada
type Errno is (None, EPERM, ENOENT, EINTR, EBADF, EAGAIN, ENOMEM, EACCES,
               EFAULT, EBUSY, EEXIST, EINVAL, ENOSYS, EOPNOTSUPP, Other);

type Outcome is record
   Ok    : Boolean;
   Error : Errno;          -- None when Ok
   Raw   : Integer;        -- the kernel's number, always kept
end record;
```

Every call returns an `Outcome`, or a record that contains one. A caller
that ignores it gets a warning from GNAT (`-gnatwr` on unused out values
**[to confirm the switch]**), and the examples never do.

### 4.3 Best-effort, reported

```ada
type Landlock_Report is record
   Result         : Outcome;
   ABI            : Natural;          -- what the kernel answered
   Asked          : Access_Set;
   Enforced       : Access_Set;       -- Asked masked by the ABI
   Dropped        : Access_Set;       -- Asked - Enforced: SAID, never silent
end record;
```

A program decides what to do with `Dropped`: refuse to start, log it, or
accept it. The library never decides for it, and never hides it.

---

## 5. The families in detail

### 5.1 Landlock

Measured on the build machine: kernel 7.1.5 answers **ABI 9**; its headers
define 19 `LANDLOCK_ACCESS_*` rights, among them file-system rights
(`EXECUTE`, `WRITE_FILE`, `READ_FILE`, `READ_DIR`, `REMOVE_DIR`,
`REMOVE_FILE`, `MAKE_*`, `REFER`, `TRUNCATE`, `IOCTL_DEV`, ...) and network
rights (`NET_BIND_TCP`, `NET_CONNECT_TCP`). Landlock appeared in Linux 5.13
(landlock_create_ruleset(2)).

```ada
type FS_Right  is (Execute, Write_File, Read_File, Read_Dir, Remove_Dir,
                   Remove_File, Make_Char, Make_Dir, Make_Reg, Make_Sock,
                   Make_Fifo, Make_Block, Make_Sym, Refer, Truncate,
                   Ioctl_Dev, ...);           -- generated, with the ABI each appeared in
type FS_Set    is array (FS_Right) of Boolean with Pack;
type Net_Right is (Bind_TCP, Connect_TCP);

procedure Create   (Handled_FS : FS_Set; Handled_Net : Net_Set;
                    R : out Ruleset; Report : out Landlock_Report);
procedure Allow    (R : in out Ruleset; Path : String; Rights : FS_Set;
                    Result : out Outcome);
procedure Allow    (R : in out Ruleset; Port : Port_Number; Rights : Net_Set;
                    Result : out Outcome);
procedure Restrict (R : in out Ruleset; Result : out Outcome);  -- sets no_new_privs first if asked
```

Each right carries **the ABI version it appeared in**, generated from
the header history **[to confirm the per-right versions from the kernel
documentation]**, which is how `Dropped` is computed before the kernel is
asked.

### 5.2 seccomp

```ada
type Action is (Allow, Errno_Return, Trap, Log, Kill_Process, Kill_Thread,
                User_Notify);
type Rule is record
   Syscall : Syscall_Name;          -- generated per architecture
   Act     : Action;
   Code    : Errno := EPERM;        -- for Errno_Return
   --  optional argument comparisons, bounded count
end record;

procedure Compile (Rules : Rule_List; Default : Action;
                   Arch : Architecture;
                   Prog : out BPF.Program; Result : out Build_Verdict)
  with Post => (if Result = Built then
                  BPF.Is_Valid (Prog)            -- every jump in range, length bounded
                  and BPF.Checks_Arch_First (Prog, Arch));
procedure Load (Prog : BPF.Program; Sync_Threads : Boolean;
                Result : out Outcome);
```

The builder (`Linux_Sys.BPF`) is **SPARK, proved**:

- every jump offset lands inside the program;
- the program's length is at most the kernel's limit **[BPF_MAXINSNS, to
  confirm the value]**;
- the first instructions load the architecture and kill on a mismatch;
- every path ends in a `RET`.

The syscall-name table per architecture is generated from the kernel's
syscall tables **[to confirm the source: `unistd.h` or the
`syscall_*.tbl` files]**, and checked by the probe.

### 5.3 Capabilities and privileges

`no_new_privs` (`prctl`), the five capability sets through `capget` and
`capset` with version 3 structures **[to confirm]**, bounding-set drops,
ambient capabilities, and securebits. Capabilities are an enumeration
generated from `<linux/capability.h>`. The typed API makes the common
sequence one call: *keep these capabilities, drop all others from every
set, lock it*.

### 5.4 `AF_PACKET` and classic BPF

From packet(7): `SOCK_RAW` delivers the frame with its link-layer header,
`SOCK_DGRAM` removes it; a filter is attached with `SO_ATTACH_FILTER`
(classic) or `SO_ATTACH_BPF` (eBPF; out of scope here).

```ada
procedure Open    (Kind : Raw_Or_Cooked; Protocol : EtherType;
                   S : out Packet_Socket; Result : out Outcome);
procedure Bind    (S : Packet_Socket; Interface_Index : Positive;
                   Result : out Outcome);
procedure Promisc (S : Packet_Socket; Interface_Index : Positive; On : Boolean;
                   Result : out Outcome);   -- membership, not an interface flag
procedure Filter  (S : Packet_Socket; Prog : BPF.Program;
                   Result : out Outcome);
procedure Receive (S : Packet_Socket; Into : out Byte_Array; Last : out Natural;
                   From : out Link_Address; Result : out Outcome);
```

Ring buffers (`PACKET_RX_RING`, `TPACKET_V3`) are a later milestone: they
need a memory-mapped structure whose layout is the classic place to get
wrong.

### 5.5 rtnetlink

The netlink message format is a header followed by attributes, each with
its own length and alignment **[to confirm the alignment rule and the
header layout in netlink(7)]**.
Both directions are pure functions over byte arrays, so they are written
in **SPARK and proved**, like any parser of untrusted input: the kernel
is trusted, but a library that walks attributes with lengths is exactly
where an off-by-one reads past a buffer.

```ada
procedure Dump_Neighbours (Family : Address_Family;
                           Each : not null access procedure (N : Neighbour);
                           Result : out Outcome);
procedure Dump_Routes     (...);
procedure Dump_Links      (...);
procedure Dump_Addresses  (...);
procedure Subscribe       (Groups : Group_Set; S : out Netlink_Socket;
                           Result : out Outcome);   -- change events
```

A `Neighbour` record holds the address, the link-layer address, the
interface index, the state set and the flags. Entries in states such as
`NOARP` or on multicast addresses are reported with their state rather
than filtered, and the caller decides **[to confirm the state list in
rtnetlink(7)]**.

### 5.6 memfd

`memfd_create` with `MFD_CLOEXEC` and `MFD_ALLOW_SEALING`, `ftruncate`,
writes, and `F_ADD_SEALS` with a typed seal set. A sealed memfd is how a
program hands a secret to a child or to a library that only reads paths,
without the secret ever touching a file system.

### 5.7 Service manager protocol

Readiness (`READY=1`), status (`STATUS=...`), watchdog (`WATCHDOG=1` at
half the interval the manager gives), and socket activation (descriptors
from 3, their count and names in the environment, checked against the
process id) **[to confirm every variable name and rule against
sd_notify(3) and sd_listen_fds(3), and the abstract-namespace form of
the notification socket]**. Implemented as a datagram to a Unix socket
and an environment read: no libsystemd, which matters for static and
minimal builds.

---

## 6. Constants: generated, then checked

The core of the project's value. For each architecture:

1. **The generator** reads `<linux/landlock.h>`, `<linux/seccomp.h>`,
   `<linux/filter.h>`, `<linux/if_packet.h>`, `<linux/rtnetlink.h>`,
   `<linux/memfd.h>`, `<linux/capability.h>` and the syscall tables, and
   emits `Linux_Sys.Raw.Constants_<arch>.ads`. All six headers are
   present on the measuring machine (Appendix A).
2. **The probe** is a C program, built from the same headers, that prints
   every constant, every `sizeof` and every `offsetof` the Ada side
   relies on.
3. **The check** compares the probe's output with what the Ada
   representation clauses declare. Any difference fails CI.
4. **A header update** (a new kernel) regenerates the file, and the diff
   is reviewed like code: a new Landlock right appears as a new
   enumeration literal with its ABI version.

The generated files are committed, so a user builds with no headers
installed. The probe runs in the project's CI, on every supported
architecture.

---

## 7. Testing

| level | how | privilege |
|---|---|---|
| builders and parsers (BPF, netlink) | SPARK proof, plus unit tests with fixtures; netlink fixtures captured from a real kernel, with provenance | none |
| constants | the probe of §6 | none |
| Landlock | apply a ruleset in a child process; check that a forbidden open fails with `EACCES` and an allowed one succeeds; check `Dropped` on a kernel with a lower ABI | none: Landlock is unprivileged |
| seccomp | load a filter in a child; call an allowed and a denied syscall; check the action | none, with `no_new_privs` |
| capabilities | inside `unshare -r` | none (a user namespace) |
| `AF_PACKET`, rtnetlink | inside `unshare -rn`: a veth pair, frames sent and received, a neighbour added and dumped | none (measured: the namespace has the full capability set) |
| service protocol | a test that plays the manager: a datagram socket, the environment set | none |
| **kernel matrix** | the integration tests in QEMU guests across kernels from 5.13 (Landlock's first) to current **[to confirm a tool: virtme-ng or plain QEMU with a small initramfs]** | CI |

The kernel matrix is what makes best-effort trustworthy: the tests
assert the exact `Dropped` set expected for each kernel's ABI.

---

## 8. API stability and versioning

- Semantic versions. The typed layer is stable within a major version.
- New kernel features arrive as **new enumeration literals**, a minor
  version, so a `case` over them in user code gets a compile-time warning
  to handle the new value: Ada's completeness check doing a job here.
- `Linux_Sys.Raw` is marked unstable: it follows the kernel.

---

## 9. Security of the library itself

- **No allocation in the confinement path** after the ruleset and the
  filter are built: confinement happens early, and a failure must leave
  the process in a known state.
- **Order enforced**: the typed API refuses to `Restrict` after `Load`
  is called on a filter that blocks `landlock_restrict_self`, and the
  documentation gives one canonical order (capabilities, `no_new_privs`,
  Landlock, seccomp last) **[to confirm against each man page's
  interactions]**.
- **A `SECURITY.md`** and a private reporting channel: a defect here
  weakens every user's sandbox.

---

## 10. Roadmap

| milestone | content | done when |
|---|---|---|
| **M0** reading | netlink(7) and rtnetlink(7) whole, sd_notify(3) and sd_listen_fds(3), the kernel's Landlock and seccomp documentation, the syscall tables | each [to confirm] point answered from its source and the document amended |
| **M1** constants | generator, probe, check, for x86-64 | CI fails on a deliberately corrupted constant (a planted test) |
| **M2** Landlock + privileges | §5.1 and §5.3, best-effort reporting | the unprivileged tests pass on the build kernel; `Dropped` is right on at least two older kernels in QEMU |
| **M3** BPF builder + seccomp | §5.2, proved | silver proof plus the four properties of §5.2 as postconditions; a filter test suite |
| **M4** packet + netlink | §5.4 and §5.5, netlink codec proved | the veth tests pass in `unshare -rn` |
| **M5** memfd + service protocol | §5.6 and §5.7 | a service example runs under the real manager with readiness and watchdog |
| **M6** aarch64 | constants, probe and tests on aarch64 | CI on both architectures |
| **M7** publication | Alire crate, documentation, examples (§11) | a stranger's CI reproduces the matrix |
| **M8** later families | packet rings, namespaces, cgroups, eBPF loading (each a decision) | — |

---

## 11. Examples

- **sandbox-me**: a program that confines itself (keep `CAP_NET_RAW`,
  read only `/etc/myapp`, write only `/var/lib/myapp`, no network bind,
  a seccomp allow-list) and prints its `Landlock_Report`.
- **arp-watch**: an `AF_PACKET` socket with an ARP filter, confined.
- **neighbours**: the neighbour table dumped, then followed by events.
- **notify-service**: readiness and watchdog under the service manager,
  socket-activated.

---

## 12. Risks and open questions

| risk | what shows it | answer |
|---|---|---|
| The kernel changes a structure or adds a right | the probe fails on a new kernel | that is the point: the failure is loud and the diff reviewed |
| Variadic `syscall` on other ABIs | a test on aarch64 | `C_Variadic_1` measured on x86-64; aarch64 measured in M6, a C shim otherwise |
| A sandbox that is too strict breaks users | user reports | `Dropped` and dry-run modes (seccomp `Log` action) in the API |
| Scope creep into a full system library | the roadmap grows | §3's non-goals; later families are decisions |
| Licence | the maintainers decide | Apache-2.0 or MIT for adoption by companies and projects alike |

---

## 13. Repository layout

```
linux-sys/
  alire.toml
  linux_sys.gpr
  src/
    linux_sys.ads                    -- Errno, Outcome
    linux_sys-raw.ads                -- imports
    linux_sys-raw-constants_x86_64.ads   -- GENERATED
    linux_sys-raw-constants_aarch64.ads  -- GENERATED
    linux_sys-landlock.ad[sb]
    linux_sys-seccomp.ad[sb]
    linux_sys-bpf.ad[sb]             -- SPARK, proved
    linux_sys-caps.ad[sb]
    linux_sys-packet.ad[sb]
    linux_sys-netlink.ad[sb]
    linux_sys-netlink-codec.ad[sb]   -- SPARK, proved
    linux_sys-memfd.ad[sb]
    linux_sys-service.ad[sb]
  gen/
    generate.py                      -- headers -> constants
    probe.c                          -- prints values, sizes, offsets
    check.py                         -- compares probe and Ada
  tests/
    unit/  namespaced/  kernels/     -- the three test levels
  examples/
    sandbox-me/  arp-watch/  neighbours/  notify-service/
  docs/
    families.md  best-effort.md  constants.md  ordering.md  SECURITY.md
```

---

## Appendix A — measurements behind this document

21 October 2026, Linux x86-64:

```bash
uname -r                                     # 7.1.5-76070105-generic
# Landlock ABI, from Python and from Ada (syscall 444 = landlock_create_ruleset,
# flags = LANDLOCK_CREATE_RULESET_VERSION):
#   Python ctypes: 9
#   Ada, Import of `syscall` with Convention => C_Variadic_1, GNAT 13.3: 9
grep -c 'define LANDLOCK_ACCESS' /usr/include/linux/landlock.h   # 19
dpkg -l linux-libc-dev                       # 7.1.5
ls /usr/include/linux/{landlock,seccomp,rtnetlink,if_packet,filter,memfd}.h   # all present
unshare -rn sh -c 'id -u; grep CapEff /proc/self/status'
#   0
#   CapEff: 000001ffffffffff
alr search --crates | grep -i -E 'linux|posix|landlock|seccomp|netlink|systemd|capab|socket'
#   florist, florist_blady, epoll, inotify, evdev, socketcan, spoon,
#   libgpiod, libsimpleio, linux_hal, bbs_embed_linux, muntsos_*;
#   nothing for landlock, seccomp, netlink, capabilities or systemd
```
