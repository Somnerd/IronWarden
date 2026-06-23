fn main() {
    cc::Build::new()
        .file("src/glibc_compat.c")
        .compile("glibc_compat");
}
