#[macro_use] extern crate log;
#[macro_use] extern crate vault;

fn main() {
  vault::connect("<your vault>", "<your key>", "<your secret>");
}
