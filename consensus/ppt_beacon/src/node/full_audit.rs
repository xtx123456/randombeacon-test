//! One authenticated disclosure per provider; full local commitment reconstruction.
//! A bad provider proof is never evidence against the dealer. Dealer evidence
//! is anchored to public RBC roots and replays the exact original encodings.
use std::collections::{BTreeMap,HashSet};
use std::sync::Arc;
use async_recursion::async_recursion;
use crypto::aes_hash::HashState;
use crate::node::merkle::MerkleTree;
use crypto::hash::{do_hash,Hash};
use crypto::gf2::Gf2Profile;
use num_bigint::BigUint;
use serde::{Serialize,Deserialize};
use types::{Replica,Round};
use types::beacon::{AvssRecipientPayload,Val};
use super::{Context,oec::{self,Field,OecCache},wire::{self,PptWire,PublicBundle},share_pipeline};
use super::shoup_smart::{rel_msg_dst::{EchoPayload,ForwardPayload,RelMsgDstState},reed_solomon::RsEncoder,
    sec_msg_dst::{decrypt_with_share,encrypt_with_share},sec_key_dst::{parse_share,serialize_share}};

#[derive(Debug,Clone,Serialize,Deserialize)]
pub(crate) struct AuditValues {
    pub secrets:Vec<Val>,pub masks:Vec<Val>,pub nonces:Vec<Val>,pub f_large:Option<Vec<Val>>,pub providers:Vec<Replica>,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub(crate) struct DealerDisclosure {
    pub dealer:Replica,pub root:Hash,
    pub original:Option<AvssRecipientPayload>,pub recovered:Option<AuditValues>,
    /// Actual per-instance transport key share, not the commitment nonce.
    pub key:Option<Vec<u8>>,
    /// Original provider shard of EVERY recipient's key/cipher message.
    pub key_row:Vec<EchoPayload>,pub cipher_row:Vec<EchoPayload>,
}
/// One complaint-authorized audit of one dealer's main batch.
#[derive(Default)]
pub(crate) struct FullAuditState {
    sent:bool,inflight:bool,version:u64,attempted:Option<u64>,
    rows:BTreeMap<Replica,DealerDisclosure>,authenticated:HashSet<Replica>,
    cache:Option<OecCache>,pub complete:bool,
}
pub(crate) struct FullAuditCompletion {
    round:Round,dealer:Replica,version:u64,result:Option<Option<String>>,
    rejected:Vec<Replica>,cache:OecCache,error:Option<String>,
}

fn public_root(bundle:&PublicBundle)->Hash {do_hash(&super::public_rbc::transcript(&bundle.public).serialize_ctrbc())}
fn valid_row(row:&[EchoPayload],root:Hash,provider:Replica,n:usize,_hash:&HashState)->bool {
    row.len()==n && row.iter().enumerate().all(|(recipient,e)|
        e.meta_root==root&&e.frag_idx==provider&&e.meta_path.matches_leaf(recipient,n)
        &&e.meta_path.root()==root&&e.meta_path.item()==do_hash(&e.msg_root)&&crate::node::merkle::validate(&e.meta_path)
        &&e.frag_path.matches_leaf(provider,n)&&e.frag_path.root()==e.msg_root
        &&e.frag_path.item()==do_hash(e.fragment.as_bytes())&&crate::node::merkle::validate(&e.frag_path))
}
fn row_shape(row:&[EchoPayload],provider:Replica,n:usize,fragment_bytes:usize)->bool {
    row.is_empty() || (row.len()==n && row.iter().enumerate().all(|(recipient,e)|
        e.frag_idx==provider && e.fragment.len()<=fragment_bytes
        &&e.meta_path.matches_leaf(recipient,n)&&e.frag_path.matches_leaf(provider,n)))
}
fn valid_entries(entries:&[DealerDisclosure],dealers:&[Replica],batch:usize,n:usize,
    f:usize,provider:Replica,binary:bool,proofless:bool)->bool {
    let plain=match super::payload_limits::plaintext(batch,n,binary,proofless,true){Some(v)=>v,None=>return false};
    let cipher=match super::payload_limits::fragment(plain,n,f){Some(v)=>v,None=>return false};
    let key=match super::payload_limits::fragment(66,n,f){Some(v)=>v,None=>return false};
    entries.len()==dealers.len()&&entries.iter().zip(dealers).all(|(e,d)|e.dealer==*d
        &&row_shape(&e.key_row,provider,n,key)&&row_shape(&e.cipher_row,provider,n,cipher)
        &&e.original.as_ref().map(|p|p.secrets.len()==batch&&p.nonces.len()==batch&&p.mask_shares.len()==batch
            &&p.mps.len()==(if proofless{0}else{batch})&&p.mps.iter().all(|proof|proof.matches_leaf(provider,n))
            &&p.f_large_shares.as_ref().map(|v|v.len()==batch).unwrap_or(true)).unwrap_or(true)
        &&e.recovered.as_ref().map(|p|p.secrets.len()==batch&&p.nonces.len()==batch&&p.masks.len()==batch
            &&p.f_large.as_ref().map(|v|v.len()==batch).unwrap_or(true)&&p.providers.len()<=n).unwrap_or(true)
        &&e.key.as_ref().map(|k|k.len()==66).unwrap_or(true))
}

enum VectorRecovery { Waiting, Fault(String), Values(Vec<Vec<u8>>) }
/// Recover the COMMITTED codewords, not an invented tree of plaintext shares.
fn committed_vector(root:Hash,rows:&[(Replica,Vec<EchoPayload>)],n:usize,f:usize,hash:Arc<HashState>)->VectorRecovery {
    if rows.len()<n-2*f{return VectorRecovery::Waiting;}
    let mut verifier=RelMsgDstState::new(0,n,f,0,hash).expect("validated RMD parameters");verifier.bind_root(root);
    let mut values=Vec::with_capacity(n);
    for recipient in 0..n {
        let selected:Vec<_>=rows.iter().take(n-2*f).map(|(_,row)|&row[recipient]).collect();let first=selected[0];
        if selected.iter().any(|e|e.msg_root!=first.msg_root){return VectorRecovery::Fault("conflicting committed message roots".into());}
        let proof=ForwardPayload {meta_root:root,my_meta_path:first.meta_path.clone(),my_msg_root:first.msg_root,
            forwarder_idx:recipient,fragments:selected.iter().map(|e|(e.frag_idx,e.frag_path.clone(),e.fragment.clone())).collect()};
        match verifier.check_forward(recipient,&proof) {
            Ok(Some(bytes))=>values.push(bytes),
            Ok(None)=>return VectorRecovery::Fault("original committed fragments are not the specified RS codeword".into()),
            Err(_)=>return VectorRecovery::Waiting, // Provider evidence is insufficient/invalid, not dealer guilt.
        }
    }VectorRecovery::Values(values)
}
fn rebuild_vector(messages:&[Vec<u8>],n:usize,f:usize,hash:&HashState)->Result<Hash,String> {
    if messages.len()!=n{return Err("message vector length".into());}
    let encoder=RsEncoder::new(n,f).map_err(|e|e.to_string())?;let mut roots=Vec::with_capacity(n);
    for message in messages {let fragments=encoder.encode(message).map_err(|e|e.to_string())?;
        roots.push(MerkleTree::new(fragments.iter().map(|v|do_hash(v.as_bytes())).collect(),hash).root());}
    Ok(MerkleTree::new(roots.iter().map(|r|do_hash(r)).collect(),hash).root())
}

enum DealerResult { Waiting, Complete(Option<String>) }
fn audit_dealer(bundle:&PublicBundle,input:&[(Replica,DealerDisclosure)],batch:usize,n:usize,f:usize,
    small:&BigUint,large:&BigUint,profile:Option<Gf2Profile>,hash:Arc<HashState>,cache:&mut OecCache,
    authenticated:&HashSet<Replica>,rejected:&mut Vec<Replica>)->DealerResult {
    let root=public_root(bundle);
    let main_binding=bundle.challenge_root.as_ref();
    let input:Vec<_>=input.iter().filter(|(_,e)|e.root==root).collect();
    let mut payloads:BTreeMap<Replica,AvssRecipientPayload>=BTreeMap::new();let mut actual_keys=None;let mut actual_payloads=None;
    if let Some((key_root,cipher_root))=bundle.secmsg_roots {
        let mut key_rows=Vec::new();let mut cipher_rows=Vec::new();
        for (provider,e) in &input {
            if !e.key_row.is_empty(){if valid_row(&e.key_row,key_root,*provider,n,&hash){key_rows.push((*provider,e.key_row.clone()));}else if authenticated.contains(provider){rejected.push(*provider);}}
            if !e.cipher_row.is_empty(){if valid_row(&e.cipher_row,cipher_root,*provider,n,&hash){cipher_rows.push((*provider,e.cipher_row.clone()));}else if authenticated.contains(provider){rejected.push(*provider);}}
        }
        let keys=match committed_vector(key_root,&key_rows,n,f,hash.clone()) {VectorRecovery::Values(v)=>v,VectorRecovery::Waiting=>return DealerResult::Waiting,VectorRecovery::Fault(e)=>return DealerResult::Complete(Some(e))};
        let ciphers=match committed_vector(cipher_root,&cipher_rows,n,f,hash.clone()) {VectorRecovery::Values(v)=>v,VectorRecovery::Waiting=>return DealerResult::Waiting,VectorRecovery::Fault(e)=>return DealerResult::Complete(Some(e))};
        let key_prime=super::reserve_transport::key_prime();let mut original=Vec::with_capacity(n);
        for provider in 0..n {
            let key=match parse_share(&key_prime,&keys[provider]){Some(k)=>k,None=>return DealerResult::Complete(Some("noncanonical committed transport key".into()))};
            let bytes=match decrypt_with_share(&key_prime,&key,&ciphers[provider]){Some(v)=>v,None=>return DealerResult::Complete(Some("committed ciphertext cannot be decrypted".into()))};
            let payload=match super::batch_degree_test::decode_payload(&bytes,profile,batch,0){Some(p)=>p,None=>return DealerResult::Complete(Some("committed plaintext is not a canonical AVSS payload".into()))};
            if super::batch_degree_test::encode_payload(&payload,profile,batch,0).as_ref()!=Some(&bytes)||payload.secrets.len()!=batch||payload.nonces.len()!=batch||payload.mask_shares.len()!=batch
                ||payload.mps.len()!=(if main_binding.is_some(){0}else{batch})||match (profile,&payload.f_large_shares){(Some(_),None)=>false,(None,Some(v))=>v.len()!=batch,_=>true}
                {return DealerResult::Complete(Some("committed plaintext has invalid canonical batch encoding".into()));}
            payloads.insert(provider,payload.clone());original.push(payload);
        }
        for (provider,e) in &input {if authenticated.contains(provider){
            if e.original.as_ref().map(|p|p!=&original[*provider]).unwrap_or(false)
                ||e.key.as_ref().map(|k|k!=&keys[*provider]).unwrap_or(false){rejected.push(*provider);}
        }}actual_keys=Some(keys);actual_payloads=Some(original);
    }else{
        // Lite comparison: original point paths authenticate the OEC inputs.
        // They do not replace the full polynomial/tree reconstruction below.
        for (provider,e) in &input {if let Some(p)=&e.original {
            if share_pipeline::validate_original(&bundle.public,p,0,batch,*provider,n,f,small,large,profile,&hash,None){payloads.insert(*provider,p.clone());}
            else if authenticated.contains(provider){rejected.push(*provider);}
        }}if payloads.len()<2*f+1{return DealerResult::Waiting;}
    }
    let secret_field=match profile{Some(p)=>Field::Binary(Gf2Profile::new(p.w_p,p.w_p).expect("base field")),None=>Field::Prime(small.clone())};
    let mask_field=match profile{Some(p)=>Field::Binary(p),None=>Field::Prime(large.clone())};let nonce_field=Field::Prime(large.clone());
    let mut rebuilt:Vec<_>=(0..n).map(|_|AvssRecipientPayload::new(Vec::with_capacity(batch),Vec::with_capacity(batch),Vec::with_capacity(batch),
        profile.is_none().then(||Vec::with_capacity(batch)),Vec::with_capacity(batch))).collect();
    let mut tree_leaves=Vec::with_capacity(batch);
    // The binary main batch has only one mask polynomial: decode it once.
    let shared_mask=if profile.is_some(){
        let points=payloads.iter().map(|(provider,p)|(*provider,p.mask_shares[0].to_vec())).collect();
        oec::decode(&mask_field,f,f,n,&points,cache)
    }else{None};
    let shared_mask_values=shared_mask.as_ref().map(|mask|(0..n)
        .map(|provider|oec::val(&mask.at_point(provider)).expect("decoded mask is canonical")).collect::<Vec<_>>());
    for coin in 0..batch {
        let points=|select:fn(&AvssRecipientPayload,usize)->Val|payloads.iter().map(|(p,v)|(*p,select(v,coin).to_vec())).collect();
        let secret=oec::decode(&secret_field,f,f,n,&points(|p,i|p.secrets[i]),cache);
        let mask=if profile.is_some(){shared_mask.clone()}else{oec::decode(&mask_field,f,f,n,&points(|p,i|p.mask_shares[i]),cache)};
        let nonce=oec::decode(&nonce_field,f,f,n,&points(|p,i|p.nonces[i]),cache);
        let lifted=if profile.is_none(){oec::decode(&nonce_field,f,f,n,&points(|p,i|p.f_large_shares.as_ref().unwrap()[i]),cache)}else{None};
        let (secret,mask,nonce)=match (secret,mask,nonce){(Some(a),Some(b),Some(c))=>(a,b,c),_=>{
            return if actual_payloads.is_some(){DealerResult::Complete(Some(format!("committed original shares violate degree <= {} at coin {}",f,coin)))}else{DealerResult::Waiting};
        }};
        if profile.is_none()&&lifted.is_none(){return if actual_payloads.is_some(){DealerResult::Complete(Some("committed lifted shares violate degree bound".into()))}else{DealerResult::Waiting};}
        let mut leaves=Vec::with_capacity(n);
        for provider in 0..n {
            let secret=oec::val(&secret.at_point(provider)).unwrap();
            let mask=match &shared_mask_values{Some(values)=>values[provider],None=>oec::val(&mask.at_point(provider)).unwrap()};
            let nonce=oec::val(&nonce.at_point(provider)).unwrap();
            let p=&mut rebuilt[provider];p.secrets.push(secret);p.mask_shares.push(mask);p.nonces.push(nonce);
            let leaf=if let Some(lifted)=&lifted {let value=oec::val(&lifted.at_point(provider)).unwrap();p.f_large_shares.as_mut().unwrap().push(value);
                types::beacon::avss_commit_leaf(&secret,&mask,&value,&nonce)}else{types::beacon::avss_commit_leaf_gf2(&secret,&mask,&nonce)};
            leaves.push(leaf);
        }
        tree_leaves.push(leaves);
    }
    let trees=MerkleTree::build_trees(tree_leaves,&hash);
    for (coin,tree) in trees.iter().enumerate(){
        if tree.root()!=bundle.public.root_vec[coin]{return DealerResult::Complete(Some(format!("fully rebuilt share commitment differs at coin {}",coin)));}
    }
    for provider in 0..n {
        if main_binding.is_none(){for tree in &trees{rebuilt[provider].mps.push(tree.gen_proof(provider));}}
        if !share_pipeline::validate_original(&bundle.public,&rebuilt[provider],0,batch,provider,n,f,small,large,profile,&hash,main_binding){
            return DealerResult::Complete(Some("rebuilt polynomials fail the agreed degree-test identity/domain binding".into()));
        }
    }
    if let Some(keys)=actual_keys {
        let key_prime=super::reserve_transport::key_prime();let key_field=Field::Prime(key_prime.clone());
        let points=keys.iter().enumerate().map(|(p,v)|(p,v.clone())).collect();
        let polynomial=match oec::decode(&key_field,f,f,n,&points,cache){Some(p)=>p,None=>return DealerResult::Complete(Some("original key sharing violates degree bound".into()))};
        let mut key_messages=Vec::with_capacity(n);let mut ciphertexts=Vec::with_capacity(n);
        for provider in 0..n {
            let key=BigUint::from_bytes_be(&polynomial.at_point(provider));
            key_messages.push(serialize_share(&key_prime,&key).expect("decoded key is in field"));
            let plaintext=match super::batch_degree_test::encode_payload(&rebuilt[provider],profile,batch,0){
                Some(bytes)=>bytes,None=>return DealerResult::Complete(Some("rebuilt batch mask layout is not canonical".into()))};
            ciphertexts.push(encrypt_with_share(&key_prime,&key,&plaintext));
        }
        let roots=bundle.secmsg_roots.unwrap();
        let new_key=rebuild_vector(&key_messages,n,f,&hash);let new_cipher=rebuild_vector(&ciphertexts,n,f,&hash);
        if new_key.as_ref().ok()!=Some(&roots.0)||new_cipher.as_ref().ok()!=Some(&roots.1){
            return DealerResult::Complete(Some("fully rebuilt key/ciphertext encoding Merkle roots differ".into()));
        }
    }
    // Derived disclosures are diagnostics, not extra unverified interpolation points.
    for (provider,e) in &input {if authenticated.contains(provider){if let Some(v)=&e.recovered {
        let expected=&rebuilt[*provider];if v.secrets!=expected.secrets||v.masks!=expected.mask_shares||v.nonces!=expected.nonces||v.f_large!=expected.f_large_shares{rejected.push(*provider);}
    }}}
    DealerResult::Complete(None)
}

impl Context {
    /// A verified complaint reveals only a corrupt dealer's MAIN instance.
    /// Main and reserve transports are independently generated in batch_wssinit.
    /// A malicious alias is rejected here rather than disclosing reserve material.
    fn dealer_audit_authorized(&self,round:Round,dealer:Replica)->bool {
        if !self.awss_selected(round,dealer) || !self.awss_recovery.get(&(round,dealer)).map(|s|s.has_complaint()).unwrap_or(false) {return false;}
        let bundle=match self.avss_public_bundles.get(&(round,dealer)){Some(b)=>b,None=>return false};
        match (bundle.secmsg_roots,bundle.reserve_roots) {
            (Some((k,c)),Some((rk,rc)))=>k!=rk && k!=rc && c!=rk && c!=rc,
            _=>false,
        }
    }

    /// Compatibility hook: inspect only already-authorized complaint targets.
    #[async_recursion]
    pub(crate) async fn try_start_full_audit(&mut self,round:Round) {
        let dealers:Vec<_>=self.awss_recovery.iter().filter(|((r,_),s)|*r==round && s.has_complaint()).map(|((_,d),_)|*d).collect();
        for dealer in dealers {self.try_start_dealer_audit(round,dealer).await;}
    }

    #[async_recursion]
    pub(crate) async fn try_start_dealer_audit(&mut self,round:Round,dealer:Replica) {
        if !self.dealer_audit_authorized(round,dealer){return;}
        let sent=self.full_audit.get(&(round,dealer)).map(|s|s.sent).unwrap_or(false);
        if !sent {
            let root=match self.awss_root(round,dealer){Some(r)=>r,None=>return};
            let (_,key_row,cipher_row)=match self.avss_secmsg_state.get(&(round,dealer)){Some(s)=>s.audit_material(),None=>return};
            let bundle=&self.avss_public_bundles[&(round,dealer)];let (kr,cr)=bundle.secmsg_roots.unwrap();
            // Never consume the send latch while our authenticated row is missing.
            if !valid_row(&key_row,kr,self.myid,self.num_nodes,&self.hash_context)
                || !valid_row(&cipher_row,cr,self.myid,self.num_nodes,&self.hash_context){return;}
            let entry=DealerDisclosure{dealer,root,original:None,recovered:None,key:None,key_row,cipher_row};
            self.full_audit.entry((round,dealer)).or_default().sent=true;
            self.broadcast(wire::encode(&PptWire::DealerAudit{round,dealer,entry:entry.clone()}),round).await;
            self.process_dealer_audit(round,dealer,entry,self.myid).await;
        }
        self.try_run_dealer_audit(round,dealer).await;
    }

    #[async_recursion]
    pub(crate) async fn process_dealer_audit(&mut self,round:Round,dealer:Replica,entry:DealerDisclosure,sender:Replica) {
        if sender>=self.num_nodes || dealer>=self.num_nodes || round>self.max_rounds
            || !valid_entries(std::slice::from_ref(&entry),&[dealer],self.batch_size,self.num_nodes,self.num_faults,sender,
                self.gf2_profile.is_some(),self.gf2_profile.is_some()&&self.transport==super::context::AvssTransport::SecMsg){return;}
        // Rows can race ahead of the complaint/ACS decision. Cache bounded rows,
        // but neither run an audit nor disclose anything until authorization.
        let state=self.full_audit.entry((round,dealer)).or_default();
        if state.complete || state.authenticated.contains(&sender){return;}
        state.rows.insert(sender,entry);state.authenticated.insert(sender);state.version+=1;
        self.try_run_dealer_audit(round,dealer).await;
    }

    #[async_recursion]
    async fn try_run_dealer_audit(&mut self,round:Round,dealer:Replica) {
        if !self.dealer_audit_authorized(round,dealer){return;}
        let state=self.full_audit.entry((round,dealer)).or_default();
        if state.inflight || state.complete || state.attempted==Some(state.version) || state.rows.len()<self.num_nodes-2*self.num_faults{return;}
        let bundle=match self.avss_public_bundles.get(&(round,dealer)){Some(b)=>b.clone(),None=>return};
        let rows=state.rows.iter().map(|(p,e)|(*p,e.clone())).collect::<Vec<_>>();
        let authenticated=state.authenticated.clone();let version=state.version;
        state.inflight=true;state.attempted=Some(version);let mut cache=state.cache.take().unwrap_or_default();
        let batch=self.batch_size;let n=self.num_nodes;let f=self.num_faults;let small=self.secret_domain.clone();let large=self.nonce_domain.clone();let profile=self.gf2_profile;let hash=self.hash_context.clone();let tx=self.full_audit_tx.clone();
        tokio::spawn(async move{
            let result=tokio::task::spawn_blocking(move||{
                let mut rejected=Vec::new();
                let result=match audit_dealer(&bundle,&rows,batch,n,f,&small,&large,profile,hash,&mut cache,&authenticated,&mut rejected){
                    DealerResult::Waiting=>None,DealerResult::Complete(reason)=>Some(reason)};
                FullAuditCompletion{round,dealer,version,result,rejected,cache,error:None}
            }).await;
            let completion=match result {Ok(c)=>c,Err(e)=>FullAuditCompletion{round,dealer,version,result:None,rejected:Vec::new(),cache:OecCache::default(),error:Some(e.to_string())}};
            let _=tx.send(completion);
        });
    }

    #[async_recursion]
    pub(crate) async fn finalize_full_audit(&mut self,completion:FullAuditCompletion) {
        let FullAuditCompletion{round,dealer,version,result,rejected,cache,error}=completion;
        let state=match self.full_audit.get_mut(&(round,dealer)){Some(s)=>s,None=>return};
        state.inflight=false;state.cache=Some(cache);let changed=state.version!=version;
        if let Some(error)=error {state.attempted=None;log::error!("[PPT][DEALER-AUDIT] worker failed round={} dealer={}: {}",round,dealer,error);return;}
        for provider in rejected {log::warn!("[PPT][AUDIT-PROVIDER-REJECT] round={} dealer={} provider={} (not dealer evidence)",round,dealer,provider);}
        if let Some(reason)=result {
            state.complete=true;state.cache=None;state.rows.clear();
            log::info!("[PPT][DEALER-AUDIT-COMPLETE] round={} dealer={} result={:?}",round,dealer,reason);
            self.maybe_release_round(round);
        }else if changed {self.try_run_dealer_audit(round,dealer).await;}
    }

    /// Evidence affects future local ABA inputs only, never transport membership.
    #[async_recursion]
    pub(crate) async fn note_verified_dealer_fault(&mut self,dealer:Replica) {
        if !self.banned_dealers.insert(dealer){return;}
        let rounds:Vec<_>=self.acs_state.iter().filter(|(_,s)|!s.finalized).map(|(r,_)|*r).collect();
        for round in rounds {self.acs_note_local_change(round).await;}
    }
}
