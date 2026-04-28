# Lighthouse Backup SDK for Go

Go SDK for Lighthouse Backup: workspace-scoped incremental, content-addressed
backup and restore with SIWE / email / API-key authentication and optional
client-side encryption.

## Overview

- **Backup pipeline**: scan → chunk → deduplicate → (optional) compress →
(optional) encrypt → upload packs → create snapshot.
- **Restore pipeline**: download → (optional) decrypt → (optional) decompress →  
verify integrity → reassemble files.

## Features

- **Auth**: SIWE (EIP-4361), email/password login + verification, and
`lh_`-prefixed API key bearer tokens.
- **Workspace-scoped** backup/restore — set a default workspace on the client
or override per call.
- **FastCDC** content-defined chunking for stable deduplication.
- **Pack uploads** to aggregate chunks for efficient object storage.
- **Bloom-assisted dedup** using server-provided filters.
- **Incremental backup** using file metadata to reuse unchanged chunk lists.
- **Canonical directory trees** for cross-language compatibility.
- **Optional client-side encryption**: passphrase-protected tenant key (TMK),
per-snapshot data encryption key (DEK) wrapped server-side, per-object keys
from HKDF over the DEK and content hash.
- **Snapshot lifecycle**: list, inspect, create, delete, prune.
- **Retention and pruning** (keep last N, keep within N days).
- **Workspace & member management** + user profile / identity / API-key APIs.
- **Restore verification** against expected chunk hashes.

## Requirements

- Go **1.24** or newer.

## Module

Go module path: **github.com/lighthouse-web3/baas-go-sdk**.

## Installation

```bash
go get github.com/lighthouse-web3/baas-go-sdk@v0.0.1
```

## Package entrypoints

- **High-level SDK client:**
  - `github.com/lighthouse-web3/baas-go-sdk/client`
  - create with `client.NewBackupClient(...)`

## Quick start

```go
package main

import (
    sdkclient "github.com/lighthouse-web3/baas-go-sdk/client"
    sdktypes "github.com/lighthouse-web3/baas-go-sdk/types"
)

func main() {
    client, err := sdkclient.NewBackupClient(sdkclient.BackupClientOptions{
        APIURL:      "https://baas.lighthouse.storage",
        APIKey:      "lh_...",
        WorkspaceID: "550e8400-e29b-41d4-a716-446655440000",
    })
    if err != nil {
        panic(err)
    }

    snap, err := client.Backup([]string{"/path/to/data"}, &sdktypes.BackupOptions{
        Description: "nightly",
    })
    if err != nil {
        panic(err)
    }
    _ = snap
}
```

## Package layout

- `client`: high-level SDK client and orchestration surface.
- `api`: typed HTTP transport + auth flows + S3 upload/download helpers.
- `pipeline`: backup/restore/rotation workflows.
- `types`: API payload and SDK option types.
- `errors`: structured API error helpers.
- `encrypt`: keyfile/TMK/DEK/HKDF/AES-GCM encryption helpers.
- `chunk`: FastCDC chunking + SHA-256 hashing.
- `dedup`: bloom filter dedup support.
- `tree`: canonical tree serialization and hashing.
- `codec`: compression/decompression helpers (zstd).
- `pool`: generic batching and bounded parallel worker helpers.
- `utils`: small shared utilities.

## Main capabilities

- Authenticate via SIWE, email/password, or a raw API key and attach a bearer
token to all subsequent calls.
- Manage **workspaces** (create/list/get/patch) and their **members**.
- Run end-to-end **backup** and **restore** against a workspace.
- Manage **snapshots**, **usage**, and apply **retention** policies.
- Provision and revoke **API keys** with scoped access.
- When encryption is enabled: create or open a **keyfile**, wrap the snapshot
**DEK** with the **TMK**, and derive per-chunk / per-tree keys for encrypting
and decrypting stored blobs.
- **TMK rotation**: re-wrap every snapshot's DEK under a new TMK without  
re-encrypting any data blobs.

