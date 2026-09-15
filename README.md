 Cross-platform endpoint protection agent written in Go, built around privilege separation, a thin privileged daemon that manages IPC, policy, and worker lifecycle, a sandboxed scanner worker that parses untrusted input, and a lower-privileged UI that never touches the filesystem directly.

This is a work in progress. The current tree implements the plumbing end‑to‑end — control socket, process separation, seccomp sandbox, and fd‑passing scanner protocol — with a stub detection engine. The detection engine, policy layer, and filesystem event source are the next milestones.

Design goals

    The privileged process never parses untrusted input. The daemon moves paths and file descriptors, but never inspects bytes.

    The parser is sandboxed and cannot escape. Dropped capabilities, no_new_privs, rlimits, fresh namespaces, and a seccomp deny‑list.

    The parser never opens files by path. The daemon passes a file descriptor over SCM_RIGHTS. The worker's open/openat/openat2 syscalls are blocked outright.

    The UI is a thin client. It sends requests over a local Unix socket; the daemon performs privileged work. The UI's compromise does not imply endpoint compromise.

    The boundaries are stable enough to swap components. The detection engine can be replaced without touching the sandbox or the daemon's control flow.
