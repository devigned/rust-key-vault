use std::fmt;
use std::str::{FromStr, from_utf8};
use std::ops::{Deref, DerefMut};
use hyper::header::{Header, HeaderFormat, Scheme};
use regex::Regex;

/// The `WWW-Authorization` header field.
#[derive(Clone, PartialEq, Show)]
pub struct WwwAuthenticate<S: Scheme>(pub S);

impl<S: Scheme> Deref for WwwAuthenticate<S> {
    type Target = S;

    fn deref<'a>(&'a self) -> &'a S {
        &self.0
    }
}

impl<S: Scheme> DerefMut for WwwAuthenticate<S> {
    fn deref_mut<'a>(&'a mut self) -> &'a mut S {
        &mut self.0
    }
}

impl<S: Scheme> Header for WwwAuthenticate<S> {
    fn header_name() -> &'static str {
        "WWW-Authenticate"
    }

    fn parse_header(raw: &[Vec<u8>]) -> Option<WwwAuthenticate<S>> {
        if raw.len() == 1 {
            match (from_utf8(unsafe { &raw[].get_unchecked(0)[] }), Scheme::scheme(None::<S>)) {
                (Ok(header), Some(scheme))
                    if header.starts_with(scheme) && header.len() > scheme.len() + 1 => {
                    header[scheme.len() + 1..].parse::<S>().map(|s| WwwAuthenticate(s)).ok()
                },
                (Ok(header), None) => header.parse::<S>().map(|s| WwwAuthenticate(s)).ok(),
                _ => None
            }
        } else {
            None
        }
    }
}

impl<S: Scheme> HeaderFormat for WwwAuthenticate<S> {
    fn fmt_header(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match Scheme::scheme(None::<S>) {
            Some(scheme) => try!(write!(fmt, "{} ", scheme)),
            None => ()
        };
        self.0.fmt_scheme(fmt)
    }
}


/// Credential holder for Basic Authentication
#[derive(Clone, PartialEq, Debug)]
pub struct BearerToken {
  /// The token
  pub token: String,
}

impl Scheme for BearerToken {
  fn scheme(_: Option<BearerToken>) -> Option<&'static str> {
    Some("Bearer")
  }

  fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", self.token)
  }
}

impl FromStr for BearerToken {
  type Err = ();
  fn from_str(s: &str) -> Result<BearerToken, ()> {
    Ok(BearerToken{ token: s.to_string() })
  }
}

/// Credential holder for Bearer Authentication
#[derive(Clone, PartialEq, Show)]
pub struct Bearer {
    /// The url to authenticate against
    pub authorization: String,
    /// The resource to authenticate on behalf
    pub resource: String
}

impl Scheme for Bearer {
    fn scheme(_: Option<Bearer>) -> Option<&'static str> {
        Some("Bearer")
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = String::from_str("authorization=\"");
        text.push_str(self.authorization.as_slice());
        text.push_str("\", resource=\"");
        text.push_str(self.resource.as_slice());
        text.push('"');
        write!(f, "{}", text)
    }
}

impl FromStr for Bearer {
    type Err = ();
    fn from_str(s: &str) -> Result<Bearer, ()> {
      match Regex::new("authorization=\"(.+?)\""){
        Ok(auth_re) => {
          match auth_re.captures(s) {
            Some(auth_cap) => {
              match Regex::new("resource=\"(.+?)\"") {
                Ok(resource_re) => {
                  match resource_re.captures(s) {
                    Some(re_cap) => {
                      Ok(Bearer {
                        authorization: auth_cap.at(1).unwrap().to_string(),
                        resource: re_cap.at(1).unwrap().to_string()
                        })
                    },
                    None => {
                      debug!("Bearer::no_resource_capture");
                      Err(())
                    }
                  }
                },
                Err(e) => {
                  debug!("Bearer::resource_regex_failed error={:?}", e);
                  Err(())
                }
              }
            },
            None => {
              debug!("Bearer::no_auth_capture");
              Err(())
            }
          }
        },
        Err(e) => {
          debug!("Bearer::auth_regex_failed error={:?}", e);
          Err(())
        }
      }
    }
}
