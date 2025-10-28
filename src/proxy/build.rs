use xdrgen;

fn main() {
    xdrgen::compile("src/efs_prot.x").expect("xdrgen efs_prot.x failed");
}
