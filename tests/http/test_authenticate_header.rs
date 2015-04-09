use vault::http::authenticate_header::*;
use hyper::header::{Headers, Header};


fn setup() {
}

test!(test_raw_auth {
  let mut headers = Headers::new();
  headers.set(WwwAuthenticate(format!("foo bar baz")));
  assert_eq!(headers.to_string(), "WWW-Authenticate: foo bar baz\r\n".to_string());
});

test!(test_raw_auth_parse {
  let header: WwwAuthenticate<String> = Header::parse_header(&[b"hello world".to_vec()]).unwrap();
  assert_eq!(header.0, "hello world");
});

test!(test_basic_auth {
  let mut headers = Headers::new();
  headers.set(WwwAuthenticate(Bearer { authorization: format!("https://login.windows.net/123"), resource: format!("https://vault.azure.net") }));
  assert_eq!(headers.to_string(), format!("WWW-Authenticate: Bearer authorization=\"https://login.windows.net/123\", resource=\"https://vault.azure.net\"\r\n"));
});

test!(test_basic_auth_parse {
  let auth: WwwAuthenticate<Bearer> = Header::parse_header(&[b"Bearer authorization=\"https://login.windows.net/123\", resource=\"https://vault.azure.net\"".to_vec()]).unwrap();
  assert_eq!(&auth.0.authorization[..], "https://login.windows.net/123");
  assert_eq!(auth.0.resource, "https://vault.azure.net");
});
