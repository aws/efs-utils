#!/bin/bash

# Regenerate src/nfs/nfs4_1_xdr.rs while preserving previous overrides that would be clobbered by
# regeneration from src/xdr/nfs_4_1_prot.x

cp src/xdr/nfs_4_1_prot.x src/xdr/nfs_4_1_prot.x.backup

cpp -C -P src/xdr/nfs_4_1_prot.x > src/xdr/nfs_4_1_prot.x.preprocessed

if [ $? -ne 0 ]; then
    echo "Error: Preprocessing src/xdr/nfs_4_1_prot.x failed"
    exit 1
fi

mv src/xdr/nfs_4_1_prot.x.preprocessed src/xdr/nfs_4_1_prot.x

xdrgen src/xdr/nfs_4_1_prot.x > src/nfs/nfs4_1_xdr.rs

if [ $? -ne 0 ]; then
    echo "Error: xdrgen src/xdr/nfs_4_1_prot.x failed"
    exit 1
fi

rustfmt src/nfs/nfs4_1_xdr.rs

if [ $? -ne 0 ]; then
    echo "Error: rustfmt src/xdr/nfs_4_1_prot.x failed"
    exit 1
fi

git apply --ignore-whitespace --whitespace=fix -C0 tools/nfs4_xdr_override.diff

if [ $? -ne 0 ]; then
    echo "Error: Failed to apply XDR overrides"
    exit 1
fi

mv src/xdr/nfs_4_1_prot.x.backup src/xdr/nfs_4_1_prot.x
