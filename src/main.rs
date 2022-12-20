
mod rsa;

use crate::rsa::*;

use num_bigint::BigInt;

fn main() {
  //let args: Vec<String> = env::args().collect();
  let t = GenRsa::new(&BigInt::from(1000));
  dbg!(&t);
  assert!(t.is_valid());
}

#[cfg(test)]
mod tests {
  use crate::rsa::*;

  #[test]
  fn gen_pair() {
    let t = GenRsa::new(500);
    dbg!(&t);
    assert!(t.is_valid());
  }
}
