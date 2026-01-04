# Migration Guide — crate `spiffe` 0.10

This guide covers migration from **spiffe 0.9.x → 0.10.0**.

---

## 1. Default features removed (breaking)

The `spiffe` crate no longer enables any features by default.

You **must explicitly enable** the functionality you use.

### Recommended defaults

**X.509 workloads (most users):**

```toml
spiffe = { version = "0.10", features = ["x509-source"] }
```

**Direct Workload API client (X.509 + JWT):**

```toml
spiffe = { version = "0.10", features = ["workload-api"] }
```

**Workload API client (X.509):**

```toml
spiffe = { version = "0.10", features = ["workload-api-x509"] }
```

**Workload API client (JWT):**

```toml
spiffe = { version = "0.10", features = ["workload-api-JWT"] }
```

---

## 2. X509Source construction changed (breaking)

`X509Source::new()` now returns `X509Source` instead of `Arc<X509Source>`.

### Before (0.9)

```rust
let source: Arc<X509Source> = X509Source::new().await?;
```

### After (0.10)

```rust
let source = X509Source::new().await?;
let cloned = source.clone();
```

`X509Source` is cheaply cloneable.

---

## 3. X.509 source module relocation

The X.509 watcher/caching API now lives under its own module.

Primary types remain available at the crate root:

```rust
use spiffe::X509Source;
```

Advanced configuration types are under:

```rust
use spiffe::x509_source::*;
```

---

## 4. Feature matrix changes (important)

### X.509 parsing

```toml
features = ["x509"]
```

### JWT model + parsing (no verification)

```toml
features = ["jwt"]
```

### JWT verification (choose exactly one)

```toml
features = ["jwt-verify-rust-crypto"]
# or
features = ["jwt-verify-aws-lc-rs"]
```

Enabling both verification backends is a compile-time error.

---

## 5. Workload API feature tiers

The Workload API is split into explicit capability tiers:

| Feature             | Description                     |
|---------------------|---------------------------------|
| `workload-api-core` | Runtime + transport substrate   |
| `workload-api-x509` | Workload API with X.509 support |
| `workload-api-jwt`  | Workload API with JWT support   |
| `workload-api-full` | X.509 + JWT                     |
| `workload-api`      | Alias for `workload-api-full`   |

Most users should continue using:

```toml
features = ["workload-api"]
```

---

## 6. Transport / endpoint changes

Endpoint parsing is under the `transport` module:

```rust
use spiffe::transport::Endpoint;
```

Accepted formats include:

* `unix:///path/to/socket`
* `unix:/path/to/socket`
* `tcp://1.2.3.4:8080`
* `tcp:1.2.3.4:8080`
* `tcp://[::1]:8080`


