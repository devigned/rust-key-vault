#![allow(unstable)]

extern crate vault;

#[macro_use] extern crate log;

mod support;

macro_rules! test {
  ($name:ident $expr:expr) => (
    #[test]
    fn $name() {
      ::support::paths::setup();
      setup();
      $expr;
    }
  )
}

mod test_vault;
mod test_hello_world;
