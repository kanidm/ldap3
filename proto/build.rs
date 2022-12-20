extern crate lalrpop;

fn main() {
    lalrpop::process_root().expect("Failed to setup lalrpop");
}
