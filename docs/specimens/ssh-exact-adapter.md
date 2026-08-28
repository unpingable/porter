# Exact SSH adapter test evidence

The additive adapter was exercised from base commit
`7f05c03caeb5ca326d0eef5b2edc2060a515cc5b` with:

```text
python3 -m compileall -q porterlib
python3 -m pytest -q
```

The suite reported 33 passing tests. Five focused exact-endpoint tests prove:

- closed profile fields, exact local-file custody, hashes, and pinned argv;
- identity response, endpoint/socket, true exit, and transcript hash recording;
- input file and transfer-archive hash recording;
- remote session substitution refusal before payload invocation; and
- known-hosts substitution refusal with an unobserved—not fabricated—exit.

The retained profile snapshot is mode `0600` and remains in local run custody.
The adapter does not create, select, contain, stop, or reconcile a VM and makes
no claim about the meaning or admissibility of returned bytes.
