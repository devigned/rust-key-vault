use std::io::MemReader;
use vault::http::authenticate_header::*;
use hyper::header::{Headers};

fn setup() {
}

fn mem(s: &str) -> MemReader {
  MemReader::new(s.as_bytes().to_vec())
}

test!(test_raw_auth {
  let mut headers = Headers::new();
  headers.set(WwwAuthenticate("foo bar baz".to_string()));
  assert_eq!(headers.to_string(), "WWW-Authenticate: foo bar baz\r\n".to_string());
});

test!(test_raw_auth_parse {
  let headers = Headers::from_raw(&mut mem("WWW-Authenticate: hello world\r\n\r\n")).unwrap();
  assert_eq!(&headers.get::<WwwAuthenticate<String>>().unwrap().0[], "hello world");
});

test!(test_basic_auth {
  let mut headers = Headers::new();
  headers.set(WwwAuthenticate(Bearer { authorization: "https://login.windows.net/123".to_string(), resource: "https://vault.azure.net".to_string() }));
  assert_eq!(headers.to_string(), "WWW-Authenticate: Bearer authorization=\"https://login.windows.net/123\", resource=\"https://vault.azure.net\"\r\n".to_string());
});

test!(test_basic_auth_parse {
  let headers = Headers::from_raw(&mut mem("WWW-Authenticate: Bearer authorization=\"https://login.windows.net/123\", resource=\"https://vault.azure.net\"\r\n\r\n")).unwrap();
  let auth = headers.get::<WwwAuthenticate<Bearer>>().unwrap();
  assert_eq!(&auth.0.authorization[], "https://login.windows.net/123");
  assert_eq!(auth.0.resource, "https://vault.azure.net");
});
