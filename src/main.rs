
mod rsa;

use crate::rsa::*;

use num_bigint::BigInt;

fn main() {
  //let args: Vec<String> = env::args().collect();
  //let t = GenRsa::new(10000);
  //dbg!(&t);
  //assert!(t.is_valid());
  
  let t = PubRsaScheme {
    n: BigInt::from(527),
    e: BigInt::from(97),
  };
  assert_eq!(t.break_scheme(), BigInt::from(193));
}

