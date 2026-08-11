fn main() {
    // The AWS-file protocol (an NFSv4.1 extension) XDR types, generated into
    // OUT_DIR and included by the `awsfile_prot` module in lib.rs.
    xdrgen::compile("src/xdr/awsfile_prot.x").expect("xdrgen awsfile_prot.x failed");
}
