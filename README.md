# Lighthouse Backup SDK for Go

Go SDK for Lighthouse Backup: incremental, content-addressed backup and restore,
SIWE authentication, optional client-side encryption, and retention workflows.

## Overview

Backup pipeline (conceptual): scan, chunk, deduplicate, optionally compress,
optionally encrypt, upload packs, create snapshot metadata.

Restore pipeline (conceptual): download, optionally decrypt, optionally
decompress, verify integrity, write files.

## Features

- **SIWE authentication** (EIP-4361) with secp256k1 signing.
- **FastCDC** content-defined chunking for stable deduplication.
- **Pack uploads** to aggregate chunks for efficient object storage.
- **Bloom-assisted dedup** using server-provided filters.
- **Incremental backup** using file metadata to reuse unchanged chunk lists.
- **Canonical directory trees** for cross-language compatibility.
- **Optional client-side encryption**: passphrase-protected tenant key (TMK),
per-snapshot data encryption key (DEK) wrapped and stored on the server,
per-object keys from HKDF over the DEK and content hash.
- **Snapshot lifecycle**: list, inspect, create, delete.
- **Retention and pruning** (e.g. keep last N, keep within N days).
- **Restore verification** against expected chunk hashes when enabled.

## Requirements

- Go **1.24** or newer.

## Module

The Go module path is **github.com/lighthouse-web3/backup-sdk-go**. Add it as a
dependency using your usual Go module workflow.

## Main capabilities

- Authenticate against the backup API and attach a JWT for subsequent calls.
- Run end-to-end **backup** and **restore** for paths you supply.
- Manage **snapshots** and **usage**, and apply **retention** policies.
- When encryption is enabled: create or open a **keyfile**, wrap the snapshot  
**DEK** with the **TMK**, and derive per-chunk / per-tree keys for encrypting  
and decrypting stored blobs.
