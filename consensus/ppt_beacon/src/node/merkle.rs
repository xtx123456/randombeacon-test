//! PPTB Merkle hashing. Share, key, ciphertext and audit paths use exactly the
//! same SHA-256 node rule, independent of the legacy BEA AES compression code.
//! Proof wire layout/indices and the existing 32-byte digest width are retained.
use crypto::aes_hash::{HashState,Proof};
use crypto::hash::{do_hash,Hash};

fn parent(left:Hash,right:Hash)->Hash {
    let mut bytes=[0u8;85];bytes[..21].copy_from_slice(b"PPTB_MERKLE_NODE_v1::");
    bytes[21..53].copy_from_slice(&left);bytes[53..].copy_from_slice(&right);do_hash(&bytes)
}
pub(crate) fn validate(proof:&Proof)->bool {
    if !proof.has_valid_shape(){return false;}
    let lemma=proof.lemma();let path=proof.path();let mut root=lemma[0];
    for (sibling,left) in lemma[1..lemma.len()-1].iter().zip(path){root=if *left{parent(root,*sibling)}else{parent(*sibling,root)};}
    root==proof.root()
}
pub(crate) fn validate_batch(proofs:&[Proof])->bool {!proofs.is_empty()&&proofs.iter().all(validate)}

#[derive(Clone,Debug)]
pub(crate) struct MerkleTree {levels:Vec<Vec<Hash>>,leaf_count:usize}
impl MerkleTree {
    pub fn new(leaves:Vec<Hash>,_legacy:&HashState)->Self {
        assert!(!leaves.is_empty(),"PPTB trees require a nonempty leaf vector");
        let leaf_count=leaves.len();let mut levels=vec![leaves];
        while levels.last().unwrap().len()>1 {
            let previous=levels.last().unwrap();let next=previous.chunks(2).map(|pair|parent(pair[0],*pair.get(1).unwrap_or(&pair[0]))).collect();levels.push(next);
        }Self{levels,leaf_count}
    }
    pub fn build_trees(leaves:Vec<Vec<Hash>>,legacy:&HashState)->Vec<Self>{leaves.into_iter().map(|v|Self::new(v,legacy)).collect()}
    pub fn root(&self)->Hash {self.levels.last().unwrap()[0]}
    pub fn gen_proof(&self,mut index:usize)->Proof {
        assert!(index<self.leaf_count);let mut lemma=vec![self.levels[0][index]];let mut path=Vec::new();
        for level in &self.levels[..self.levels.len()-1] {
            lemma.push(*level.get(index^1).unwrap_or(&level[index]));path.push(index&1==0);index/=2;
        }lemma.push(self.root());Proof::new(lemma,path)
    }
}
