#[macro_use] extern crate log;
#[macro_use] extern crate vault;

fn main() {
  vault::connect("hello", "world");
}
