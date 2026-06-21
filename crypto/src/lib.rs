#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

pub mod hash;
pub mod aes_hash;
pub mod gf2;

mod crypto;
pub use crypto::*;

pub mod error;
pub mod secret;