#![crate_name="vault"]
#![feature(core)]
#![feature(collections)]

#[macro_use] extern crate log;
extern crate hyper;
extern crate url;
extern crate regex;
extern crate "rustc-serialize" as rustc_serialize;

pub mod http;
