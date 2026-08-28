# Exact SSH endpoint profile v1

`ssh-exact:<absolute-profile-path>` connects Porter to one already-running SSH
endpoint. The caller owns creation, selection, containment, timeout, and
teardown of that endpoint. Porter neither launches nor manages it.

The profile is a closed JSON object with schema
`porter.ssh-exact-profile.v1`. It binds:

- a caller-defined endpoint ID and session ID;
- loopback IPv4 host and exact port;
- SSH user, executable path/hash, and fixed noninteractive options;
- owner-only client identity path and its public-key fingerprint;
- known-hosts path/hash and one contained guest host-key fingerprint;
- remote custody root and work directory;
- one exact remote identity argv; and
- a nonempty map of expected factual identity fields, including the session ID.

All local paths must be absolute, regular, non-symlink files and must not be
group/world writable. The private client key must be owner-only. The endpoint
host is exactly `127.0.0.1`; forwarding, password authentication, ambient SSH
configuration, connection sharing, and TTY allocation are disabled in the
executed argv. The profile is reloaded and matched to the record before every
operation, and the remote identity command is rerun before every push, exec, or
pull. A substitution is a courier refusal before payload invocation.

Porter records the exact transport argv, exact payload argv, true observed exit
status, transcript path/hash, input file and transfer-archive hashes, returned
artifact hashes, endpoint/socket identity, and returned guest identity. These
are facts only. The profile and adapter contain no qualification, admission,
scheduling, settlement, reconciliation, successor selection, or VM lifecycle
behavior.

The profile may contain local topology and therefore stays with local run
custody by default. It must never contain an application credential, API
secret, remote credential-store path, or credential bytes.
