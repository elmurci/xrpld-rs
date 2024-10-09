fn main() {
    prost_build::compile_protos(&["src/messaging.proto"], &["src/"])
        .expect("Compiling `src/messaging.proto`");
}