# Future Features

## Encrypted Object Graph Storage

Status: future concept, not part of the current Ward runtime.

Ward could evolve from local encrypted `.env.vault` files into a user-owned
encrypted data mounting protocol. The first proof of concept should stay narrow:
store Ward env vaults as encrypted, content-addressed objects that can live in
any storage backend, then mount them locally with Ward.

The goal is:

- encrypted data can be stored anywhere;
- storage providers and public nodes cannot read the content;
- a user can recover from any known valid piece plus the unlock flow;
- daily access uses PIN/passphrase plus the Ward key API;
- recovery access uses an exported high-entropy recovery key.

### Core Model

Do not encrypt user data directly with the PIN-derived key. Instead:

1. Generate a random data root key for the vault.
2. Encrypt env/data chunks with data keys derived from or wrapped by the data
   root key.
3. Wrap the data root key with a daily unlock wrapper derived from:
   - user PIN/passphrase;
   - Ward key API server secret;
   - vault-specific nonce/KDF metadata.
4. Also wrap the data root key with an exported recovery key.

This allows PIN changes without re-encrypting all stored data. Ward only needs
to unwrap the data root key again with a new PIN-derived wrapper.

### Object Graph

Instead of depending on one mount file, each encrypted object can carry
encrypted links to related objects. After decryption, a piece may reveal:

```json
{
  "version": 1,
  "vaultId": "...",
  "objectType": "ward.chunk",
  "epoch": 1,
  "sequence": 42,
  "prev": ["sha256:..."],
  "next": ["sha256:..."],
  "checkpoint": "sha256:...",
  "dataKeyId": "...",
  "payload": "..."
}
```

With one valid object ID and the correct unlock flow, Ward can fetch the object,
decrypt it locally, read its encrypted neighbor pointers, and walk both
directions until it reconstructs the vault graph.

### Immutable Storage Constraint

Content-addressed objects should be immutable. If an old object is edited to add
a new `next` pointer, its hash changes and can cascade through the graph.

The safer design is:

- immutable encrypted chunks;
- append-only encrypted link/update records;
- periodic encrypted checkpoints.

Checkpoints make recovery faster while still allowing recovery from a known
piece. A checkpoint can contain encrypted indexes for known heads, tails, and
recent chunks.

### Minimal Ward POC

The first implementation should target env vaults only:

1. Create an encrypted env vault using a random data root key.
2. Store the encrypted vault as one or more content-addressed objects.
3. Store daily and recovery wrappers for the data root key.
4. Publish objects to a local mock store first.
5. Delete the local `.env.vault`.
6. Recover/mount from one object ID plus PIN/passphrase and the Ward API.
7. Confirm `ward run` can use the mounted vault without writing plaintext envs.

Initial experimental commands could be:

```bash
ward vault graph init
ward vault graph push
ward vault graph pull <object-id>
ward vault graph mount <object-id>
ward vault graph recover <object-id>
```

### Storage Backends

Start with simple adapters:

- local directory mock store;
- HTTP object store;
- S3-compatible object store.

Later adapters could target:

- IPFS/IPLD;
- Filecoin;
- Arweave;
- Storj/Sia-like object storage;
- a Ward-operated public node network.

### Security Requirements

- Pointers should be encrypted so public nodes cannot map a user's full graph.
- Object IDs should be content hashes of ciphertext.
- Every decrypted object should include `vaultId` and type/version fields.
- Use authenticated encryption for every object.
- Consider owner signatures for update records and checkpoints.
- Recovery keys must be treated as master keys.
- If both PIN/passphrase and recovery key are lost, private data is unrecoverable.
- If the Ward API server secret is lost without key-version backup, affected
  daily wrappers may become unusable.

### Product Boundary

This is not a replacement for the current `.env.vault` workflow yet. It should
ship as an experimental storage layer only after the local API-derived vault
model remains stable.

The product promise, if validated, is:

> Encrypted data can live anywhere. Ward mounts it locally. Storage nodes route
> and preserve ciphertext, but never read secrets.
