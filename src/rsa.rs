//! Interface for generating an rsa
//! key pair with the GenRsa struct.
//! The PubRsaScheme allows for attempting
//! to break the rsa scheme by attempting
//! to calculate the totient of n
//! in the public rsa scheme.
//!
//! author  Matt Stetter
//! file    rsa.rs
//!

use num_bigint::{BigInt, RandBigInt};

/// The public part of the
/// RSA scheme. This stores
/// the e coefficient and
/// the n modulus base.
#[derive(Debug)]
pub struct PubRsaScheme {
  pub n: BigInt,
  pub e: BigInt,
}

/// Compares the two provided
/// big integers. If a is less
/// than b, -1 is returned. If
/// a is greater than b, 1 is
/// returned. Otherwise 0 is
/// returned.
///
/// a:          first big integer
/// b:          second big integer
/// return:     comparison value
fn cmp_bigint(a: &BigInt, b: &BigInt) -> i32 {
  let sub = a - b;
  let z = BigInt::from(0);
  if sub < z {
    -1
  } else if sub > z {
    1
  } else {
    0
  }
}

impl PubRsaScheme {

  /// Break the RSA scheme given the
  /// e coefficient and the n modulus base.
  ///
  /// self:     PubRsaScheme with n and e values
  /// return:   private d value associated with the public
  ///           RSA values
  pub fn break_scheme(&self) -> BigInt {

    // Start looking at the ceiling function
    // of the square root of n up to one
    // half of n. For each value, square it,
    // subtract n, and determine if the resultant
    // value is a square number. If it is,
    // this is the b value, which makes it
    // trivial to find the p and q values
    // and the totient of n.
    let mut a: BigInt = (&self.n.sqrt()).clone() + 1;
    loop {
      if cmp_bigint(&a, &BigInt::from(self.n.checked_div(&BigInt::from(2)).unwrap())) == 0 {
        return BigInt::from(0);
      }
      let a2 = BigInt::from(a.pow(2));
      if PubRsaScheme::is_square(&a2.checked_sub(&self.n).unwrap()) {
        break;
      }
      a += 1;
    }

    // Once b is found, calculate p, q,
    // and the totient of n.
    let b = (a.pow(2).checked_sub(&self.n).unwrap()).sqrt();
    let (p, q) = (a.checked_add(&b).unwrap(), a.checked_sub(&b).unwrap());
    let totn = p.checked_sub(&BigInt::from(1)).unwrap()
        .checked_mul(&q.checked_sub(&BigInt::from(1)).unwrap()).unwrap();

    // Use the extended euclidean algorithm
    // to get the d value given the e value
    // and the totient of n
    inv_mod(&self.e, &totn)
  }

  /// Utility function to determine if the
  /// input integer is a square number.
  ///
  /// n:        input number
  /// return:   true if square, false otherwise
  fn is_square(n: &BigInt) -> bool {
    let s = n.sqrt();
    cmp_bigint(&s.pow(2), n) == 0
  }
}

/// Contains the public and private
/// part of the RSA keypair.
/// scheme is the public part,
/// while d is the private.
#[derive(Debug)]
pub struct GenRsa {
  pub scheme: PubRsaScheme,
  pub d: BigInt,
}

/// Extended euclidean algorithm to
/// find the inverse mod of a, b
fn _euclidean(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
  if cmp_bigint(&a, &BigInt::from(0)) == 0 {
    let (bsign, bbytes) = b.to_bytes_le();
    return (BigInt::from_bytes_le(bsign, &bbytes[..]), BigInt::from(0), BigInt::from(1));
  }
  let (gcd, x1, y1) = _euclidean(&b.modpow(&BigInt::from(1), &a), a);
  let x = y1.checked_sub(&b.checked_div(&a).unwrap().checked_mul(&x1).unwrap()).unwrap();
  let y = x1;
  return (gcd, x, y);
}

/// Calculates the inverse mod of a
/// and b. (result * a == 1mod(b))
/// a:        factor with answer
/// b:        mod base
/// return:   inverse mod of a, b
fn inv_mod(a: &BigInt, b: &BigInt) -> BigInt {
  let (_, x, _) = _euclidean(a, b);
  if x < BigInt::from(0) { x + b } else { x }
}


impl GenRsa {

  /// Produces a new RSA key pair
  /// given the maximum value supplied
  /// as a parameter to the function.
  ///
  /// max:      maximum value for p, q, and e
  /// return:   RSA keypair struct
  pub fn new(max: u64) -> GenRsa {

    // Get two random prime numbers
    // less than the max value and
    // get the value of n and totient
    // of n.
    let max = BigInt::from(max);
    let p = GenRsa::rand_prime(&max);
    let q = loop { 
      let temp = GenRsa::rand_prime(&max); 
      if temp != p { break temp }
    };
    let n = p.checked_mul(&q).unwrap();
    let totn = (&p - 1) * (&q - 1);

    // e is a random number such that
    // 1 < e < totn, and it is coprime
    // with n and totient of n.
    let e = GenRsa::rand_pub(&n, &totn);

    // Find d using the extended euclidean
    // algorithm, and return the RSA pair.
    let d = inv_mod(&e, &totn);
    GenRsa {
      scheme:   PubRsaScheme { n, e },
      d,
    }
  }

  
  /// Generates a random value for
  /// e in the rsa key pair generator.
  /// Provide n and totient of n.
  ///
  /// n:        chosen n value
  /// totn:     number of values less
  ///           than n that are not co-prime
  ///           with n
  /// return:   Random e value
  fn rand_pub(n: &BigInt, totn: &BigInt) -> BigInt {
    let mut e: BigInt;
    let mut rng = rand::thread_rng();
    loop {
      e = rng.gen_bigint_range(&BigInt::from(2), &totn);
      if GenRsa::is_prime(&e) &&
        cmp_bigint(&n.modpow(&BigInt::from(1), &e), &BigInt::from(0)) != 0 &&
        cmp_bigint(&totn.modpow(&BigInt::from(1), &e), &BigInt::from(0)) != 0 {
        return e;
      }
    }
  }

  /// Returns a random prime number
  /// as BigInt that is in the range
  /// 2 <= n < max, where max is
  /// chosen by the caller.
  ///
  /// max:      maximum prime number
  /// return:   random prime number
  fn rand_prime(max: &BigInt) -> BigInt {
    let mut n: BigInt;
    let mut rng = rand::thread_rng();
    loop {
      n = rng.gen_bigint_range(&BigInt::from(2), &max);
      if GenRsa::is_prime(&n) {
        return n;
      }
    }
  }

  /// Returns true if the provided
  /// number n is prime. This function
  /// iterates through all potential
  /// factors 2..sqrt(n) and returns
  /// false if a factor is found.
  /// 
  /// n:        number to test
  /// return:   true if prime, false otherwise
  fn is_prime(n: &BigInt) -> bool {
    let sqrt: BigInt = n.sqrt();
    let mut i = BigInt::from(2);
    loop {
      if cmp_bigint(&i, &sqrt) > 0 {
        break;
      }
      if cmp_bigint(&n.modpow(&BigInt::from(1), &i), &BigInt::from(0)) == 0 {
        return false;
      }
      i += 1;  
    }
    true
  }

  /// Determines if the provided RSA
  /// scheme is valid by encrypting
  /// and decrypting a random integer
  /// value with the public and private
  /// key and ensuring the result is
  /// the same as the input.
  ///
  /// return:       true if RSA scheme is valid
  pub fn is_valid(&self) -> bool {
    let a: BigInt = rand::thread_rng().gen_bigint_range(&BigInt::from(1), &self.scheme.n);
    let first_raise = a.modpow(&self.scheme.e, &self.scheme.n);
    cmp_bigint(&first_raise.modpow(&self.d, &self.scheme.n), &a) == 0
  }
}

#[cfg(test)]
mod tests {

  use super::*;

  #[test]
  fn prime_test() {
    for _ in 0..100 {
      let n = GenRsa::rand_prime(&BigInt::from(10000));
      assert!(GenRsa::is_prime(&n));
    }
  }

  #[test]
  fn valid_rsa() {
    let t = GenRsa::new(10000);
    assert!(t.is_valid());
  }

  #[test]
  fn break_rsa() {
    let scheme = PubRsaScheme {
      n: BigInt::from(527),
      e: BigInt::from(97),
    };
    assert_eq!(scheme.break_scheme(), BigInt::from(193));
  }

  #[test]
  fn break_random_rsa() {
    let rscheme = GenRsa::new(10000);
    assert!(rscheme.is_valid());
    assert_eq!(rscheme.scheme.break_scheme(), rscheme.d);
  }
}



















