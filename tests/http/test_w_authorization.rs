use std::io::MemReader;
use vault::http::www_authorization::*;
use hyper::header::{Headers};

fn setup() {
}

fn mem(s: &str) -> MemReader {
  MemReader::new(s.as_bytes().to_vec())
}

test!(test_raw_auth {
  let mut headers = Headers::new();
  headers.set(WwwAuthorization("foo bar baz".to_string()));
  assert_eq!(headers.to_string(), "WWW-Authorization: foo bar baz\r\n".to_string());
});

test!(test_raw_auth_parse {
  let headers = Headers::from_raw(&mut mem("WWW-Authorization: hello world\r\n\r\n")).unwrap();
  assert_eq!(&headers.get::<WwwAuthorization<String>>().unwrap().0[], "hello world");
});

test!(test_basic_auth {
  let mut headers = Headers::new();
  headers.set(WwwAuthorization(Bearer { authorization: "https://login.windows.net/123".to_string(), resource: "https://vault.azure.net".to_string() }));
  assert_eq!(headers.to_string(), "WWW-Authorization: Bearer authorization=\"https://login.windows.net/123\", resource=\"https://vault.azure.net\"\r\n".to_string());
});
