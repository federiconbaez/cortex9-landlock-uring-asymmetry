# landlock-uring-asymmetry

Harness diferencial **Landlock × io_uring**: compara la misma operación por
syscall directa y por `IORING_OP_*`, bajo el mismo ruleset.

*Differential harness for Landlock × io_uring: same op via direct syscall vs
`IORING_OP_*` under one ruleset.*

## Problema / Problem

Landlock expone `LANDLOCK_ACCESS_FS_IOCTL_DEV` (ABI ≥ 5) pero no engancha
`security_uring_cmd`; `IORING_OP_URING_CMD` puede llegar al mismo surface
(BLK discard / NVMe admin) sin el check (reportes LKML jun-2026 / LSM jul-2026).
El issue [landlock-lsm/linux#23](https://github.com/landlock-lsm/linux/issues/23)
pide tests desde 2024.

## Qué está probado en esta box / Proven here

| Cosa | Estado |
|------|--------|
| Landlock ABI probe | sí (ABI 6) |
| OPENAT path-deny: syscall vs `IORING_OP_OPENAT` | **medido** → asimetría 0 |
| IOCTL_DEV vs `IORING_OP_URING_CMD` control positivo | **no** en `/dev/zero` (uring_cmd → Unsupported); binario `landlock-uring-enforce` **falla fuerte** (exit 2) |

## Medición / Measurement

```bash
cargo test --test openat_measure -- --nocapture
# o:
cargo run --quiet -- openat --workspace /tmp/ll-uring-ws
```

Resultado medido en esta box (2026-10-27):

```text
MEASURE openat_asymmetry=0.0000
```

(ambos caminos `Denied` bajo el mismo ruleset.)

## Enforcement (VM/CI)

```bash
cargo run --bin landlock-uring-enforce -- /dev/loop0
```

Exit 2 si el device no implementa `uring_cmd` o Landlock no está. Exit 0 solo
si se observa el control positivo (`syscall=Denied`, `uring=Ok`). El job CI
`enforce` no tiene `continue-on-error`.

## Fuentes leídas / Sources read

- LKML 2026-06 (Bryam Vargas: bypass IOCTL_DEV vía URING_CMD)
- linux-security-module 2026-07 (confirmación NVMe; sin hook uring_cmd)
- landlock-lsm/linux#23
- `security/landlock/fs.c` (hooks file_ioctl; sin `LSM_HOOK_INIT(uring_cmd)`)
- docs.kernel.org Landlock (`IOCTL_DEV`)

## Licencia

Apache-2.0. Copyright 2026 Federico Nicolas Báez Rizzo.
