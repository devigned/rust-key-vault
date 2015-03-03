// use vault::http::vault_client::AzureVaultClient;
// use vault::http::vault_client::VaultClient;
//
// fn setup() {
// }
//
// test!(test_get_key {
//   let mut client: AzureVaultClient = VaultClient::new("vault", "key", "secret");
//   let mykey = client.get_key("mytestkey");
//   match mykey {
//     Ok(key_wrapper) => {
//       assert_eq!(key_wrapper.attributes.enabled, Some(true));
//       assert_eq!(key_wrapper.key.kid, "mytestkey");
//     },
//     Err(err) => () // TODO: fix me
//   }
// });
//
// test!(test_delete_key {
//   let mut client: AzureVaultClient = VaultClient::new("vault", "key", "secret");
//   let mykey = client.delete_key("mytestkey");
//   match mykey {
//     Ok(key_wrapper) => {
//       assert_eq!(key_wrapper.attributes.enabled, Some(true));
//       assert_eq!(key_wrapper.key.kid, "mytestkey");
//     },
//     Err(err) => () // TODO: fix me
//   }
// });
