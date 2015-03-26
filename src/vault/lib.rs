#![crate_name="vault"]
#![feature(collections)]
#![feature(convert)]

#[macro_use] extern crate log;
extern crate hyper;
extern crate url;
extern crate regex;
extern crate rustc_serialize;

pub mod http;
