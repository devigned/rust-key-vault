#![crate_name="vault"]

#[macro_use] extern crate log;
extern crate hyper;
extern crate url;
extern crate regex;
extern crate rustc_serialize;

pub mod http;
