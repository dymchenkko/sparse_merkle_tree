#![no_main]
#![no_std]

use risc0_zkvm_guest::env;

use sparse_merkle_tree::{ default_store::DefaultStore,
    error::Error, MerkleProof,CompiledMerkleProof,
    SparseMerkleTree, traits::{Value, Hasher}, H256};
use blake2b_ref::{Blake2b, Blake2bBuilder};
#[macro_use]
extern crate alloc;

const BLAKE2B_KEY: &[u8] = &[];
const BLAKE2B_LEN: usize = 32;
const PERSONALIZATION: &[u8] = b"sparsemerkletree";

pub struct Blake2bHasher(Blake2b);

impl Default for Blake2bHasher {
    fn default() -> Self {
        let blake2b = Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        Blake2bHasher(blake2b)
    }
}

impl Hasher for Blake2bHasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.update(h.as_slice());
    }
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b][..]);
    }
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
}

type SMT<'a> = SparseMerkleTree<Blake2bHasher, Word<'a>, DefaultStore<Word<'a>>>;


#[derive(Default, Clone)]
pub struct Word<'a>(&'a str);
impl<'a> Value for Word<'a> {
   fn to_h256(&self) -> H256 {
       if self.0.is_empty() {
           return H256::zero();
       }
       let mut buf = [0u8; 32];
       let mut hasher = new_blake2b();
       hasher.update(self.0.as_bytes());
       hasher.finalize(&mut buf);
       buf.into()
   }
   fn zero() -> Self {
       Default::default()
   }
}


fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"SMT").build()
}

fn construct_smt() -> bool{
    let mut result = false;
    let key: H256;
    let keey: H256;
    let mut tree = SMT::default();
    for (i, word) in "The quick brown fox jumps over the lazy dog"
        .split_whitespace()
        .enumerate()
    {
        let key: H256 = {
            let mut buf = [0u8; 32];
            let mut hasher = new_blake2b();
            hasher.update(&(i as u32).to_le_bytes());
            hasher.finalize(&mut buf);
            buf.into()
        };
        let value = Word(word);
        tree.update(key.clone(), value.clone()).expect("update");
        let proof = tree.merkle_proof(vec![key.clone()]).expect("gen proof");
        result = proof.verify::<Blake2bHasher>(tree.root(), vec![(key, value.to_h256())]).unwrap();   
    }  
    result
}

risc0_zkvm_guest::entry!(main);

pub fn main() {
    // Load the first number from the host
    let a: u64 = env::read();
    // Load the second number from the host
    let b: u64 = env::read();
    // Verify that neither of them are 1 (i.e. nontrivial factors)
    if a == 1 || b == 1 {
        panic!("Trivial factors")
    }
    // Compute the product
    let c: u64 = a * b;
    // Commit it to the public journal
    env::commit(&construct_smt());
}
