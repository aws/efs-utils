fn main() {
    xdrgen::compile("src/xdr/awsfile_prot.x").expect("xdrgen awsfile_prot.x failed");
    // Use tools/apply_nfs4_prot.sh to regenerate this into src/nfs/nfs4_1_xdr.rs instead
    // xdrgen::compile("src/xdr/nfs_4_1_prot.x").expect("xdrgen nfs_4_1_prot.x failed");
}
