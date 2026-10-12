extern crate alloc;

use alloc::vec::Vec;
use serde::{Serialize, Deserialize};
use crate::aes_hash::HashState;

use super::Hash;

/// Merkle tree inclusion proof for data element, for which item = Leaf(Hash(Data Item)).
///
/// Lemma layout:
///
/// ```text
/// [ item h1x h2y h3z ... root ]
/// ```
///
/// Proof validation is positioned hash against lemma path to match root hash.
#[derive(Debug, Clone, Eq, PartialEq,Serialize,Deserialize)]
pub struct Proof {
    lemma: Vec<Hash>,
    path: Vec<bool>,
}

impl Proof {
    /// Creates new MT inclusion proof
    pub fn new(hash: Vec<Hash>, path: Vec<bool>) -> Proof {
        //assert!(hash.len() > 2);
        //assert_eq!(hash.len() - 2, path.len());
        Proof { lemma: hash, path }
    }

    /// Return proof target leaf
    pub fn item(&self) -> Hash {
        // Malformed network proofs are rejected by validate/validate_batch;
        // preliminary leaf comparisons must not panic before that rejection.
        self.lemma.first().copied().unwrap_or([0u8; 32])
    }

    /// Return tree root
    pub fn root(&self) -> Hash {
        self.lemma.last().copied().unwrap_or([0u8; 32])
    }

    /// Validate untrusted layout before any indexing or leaf extraction.
    pub fn has_valid_shape(&self) -> bool {
        self.lemma.len() >= 2
            && self.path.len() == self.lemma.len() - 2
            && self.path.len() < usize::BITS as usize
    }

    /// Bind a proof to the expected leaf and the actual tree depth.
    pub fn matches_leaf(&self, index: usize, leaf_count: usize) -> bool {
        if !self.has_valid_shape() || leaf_count == 0 || index >= leaf_count {
            return false;
        }
        let depth = (usize::BITS - (leaf_count - 1).leading_zeros()) as usize;
        self.path.len() == depth
            && self.path.iter().enumerate().all(|(bit, left)| {
                *left == ((index >> bit) & 1 == 0)
            })
    }

    /// Verifies MT inclusion proof
    pub fn validate(&self,hc: &HashState) -> bool {
        let size = self.lemma.len();
        if !self.has_valid_shape() {
            return false;
        }

        let mut h = self.item();
        //let mut a = A::default();

        for i in 1..size - 1 {
            //a.reset();
            h = if self.path[i - 1] {
                hc.hash_two(h, self.lemma[i].clone())
                //a.node(h, self.lemma[i].clone())
            } else {
                hc.hash_two(self.lemma[i].clone(), h)
                //a.node(self.lemma[i].clone(), h)
            };
        }

        h == self.root()
    }

    pub fn validate_batch(pfs:&Vec<Proof>, hc: &HashState) -> bool{
        if pfs.is_empty() || pfs.iter().any(|p| !p.has_valid_shape()) {
            return false;
        }
        let size_each = pfs[0].lemma.len();
        // Batch hashing requires equal depth. Mixed trees are still checked
        // individually, never indexed using another proof's depth.
        if pfs.iter().any(|p| p.lemma.len() != size_each) {
            return pfs.iter().all(|p| p.validate(hc));
        }
        let mut init_hash_vec:Vec<Hash> = Vec::new();
        for p in pfs{
            init_hash_vec.push(p.item());
        }
        let size = init_hash_vec.len();
        if size_each < 2 {
            return false;
        }
        for i in 1..size_each - 1 {
            //a.reset();
            let mut one = Vec::new();
            let mut two = Vec::new();
            let mut ind = 0;
            for pf in pfs{
                if pf.path[i-1]{
                    one.push(init_hash_vec[ind]);
                    two.push(pf.lemma[i].clone());
                }
                else {
                    one.push(pf.lemma[i].clone());
                    two.push(init_hash_vec[ind]);
                }
                ind +=1;
            }
            init_hash_vec = hc.hash_batch(one, two);
        }
        for i in 0..size{
            if init_hash_vec[i] != pfs[i].root(){
                return false;
            }
        }
        return true;
    }

    /// Returns the path of this proof.
    pub fn path(&self) -> &[bool] {
        &self.path
    }

    /// Returns the lemma of this proof.
    pub fn lemma(&self) -> &[Hash] {
        &self.lemma
    }
}
