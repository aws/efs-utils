#!/bin/bash

# First, make sure your current changes are committed or staged
git add src/nfs/nfs4_1_xdr.rs

# Generate a fresh baseline by running xdrgen without applying patches
cp src/xdr/nfs_4_1_prot.x src/xdr/nfs_4_1_prot.x.backup
cpp -C -P src/xdr/nfs_4_1_prot.x > src/xdr/nfs_4_1_prot.x.preprocessed
mv src/xdr/nfs_4_1_prot.x.preprocessed src/xdr/nfs_4_1_prot.x
xdrgen src/xdr/nfs_4_1_prot.x > src/nfs/nfs4_1_xdr_baseline.rs
rustfmt src/nfs/nfs4_1_xdr_baseline.rs

# Create a proper git-style patch
(
    echo "diff --git a/src/nfs/nfs4_1_xdr.rs b/src/nfs/nfs4_1_xdr.rs"
    echo "index $(git hash-object src/nfs/nfs4_1_xdr_baseline.rs)..$(git hash-object src/nfs/nfs4_1_xdr.rs) 100644"
    git diff --no-index --no-prefix src/nfs/nfs4_1_xdr_baseline.rs src/nfs/nfs4_1_xdr.rs | tail -n +5
) > tools/nfs4_xdr_override.diff

# Clean up
rm src/nfs/nfs4_1_xdr_baseline.rs
mv src/xdr/nfs_4_1_prot.x.backup src/xdr/nfs_4_1_prot.x