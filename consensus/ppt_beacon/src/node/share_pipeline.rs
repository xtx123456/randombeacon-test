//! PPT share-level extraction followed by polynomial OEC.
use std::collections::BTreeMap;
use std::sync::Arc;
use async_recursion::async_recursion;
use crypto::aes_hash::HashState;
use crypto::gf2::{Gf2Element,Gf2Profile};
use num_bigint::BigUint;
use types::{Replica,Round};
use types::beacon::{AvssPublicCommitMsg,AvssRecipientPayload,Val};
use super::{Context,oec::{self,Field,OecCache},wire::{self,PptWire}};

#[derive(Clone)]
struct SharePacket { dealers:Vec<Replica>, values:Arc<Vec<Val>> }
#[derive(Default)]
pub(crate) struct SharePipeline {
    matrix_inflight:bool, sent:bool, points:BTreeMap<Replica,SharePacket>,
    version:u64, decoding:bool, cache:Option<OecCache>, decoded:Vec<Option<Vec<u8>>>,
}
pub(crate) enum ShareCompletion {
    Transformed { round:Round, dealers:Vec<Replica>, values:Result<Vec<Val>,String> },
    Decoded { round:Round,version:u64,decoded:Vec<Option<Vec<u8>>>,cache:OecCache,errors:Vec<Replica> },
    Failed {round:Round,error:String},
}

pub(crate) fn slice_payload(p:&AvssRecipientPayload,start:usize,len:usize)->Option<AvssRecipientPayload> {
    let end=start.checked_add(len)?;
    Some(AvssRecipientPayload::new(p.secrets.get(start..end)?.to_vec(),p.nonces.get(start..end)?.to_vec(),
        p.mask_shares.get(start..end)?.to_vec(),match &p.f_large_shares{Some(v)=>Some(v.get(start..end)?.to_vec()),None=>None},p.mps.get(start..end)?.to_vec()))
}
pub(crate) fn join_payloads(mut a:AvssRecipientPayload,b:AvssRecipientPayload)->Option<AvssRecipientPayload> {
    a.secrets.extend(b.secrets);a.nonces.extend(b.nonces);a.mask_shares.extend(b.mask_shares);a.mps.extend(b.mps);
    match (&mut a.f_large_shares,b.f_large_shares){(Some(a),Some(b))=>a.extend(b),(None,None)=>{},_=>return None,}Some(a)
}

/// Verify original share inputs with their OWN commitment paths. The challenge
/// remains bound to the ENTIRE public root vector, including sealed reserves.
pub(crate) fn validate_original(public:&AvssPublicCommitMsg,p:&AvssRecipientPayload,
    offset:usize,len:usize,source:Replica,n:usize,f:usize,small:&BigUint,large:&BigUint,
    profile:Option<Gf2Profile>,_hash:&HashState)->bool {
    if source>=n||p.secrets.len()!=len||p.nonces.len()!=len||p.mask_shares.len()!=len||p.mps.len()!=len
        ||offset.checked_add(len).map(|end|end>public.root_vec.len()
            ||(profile.is_none()&&end>public.degree_test_coeffs.len())).unwrap_or(true)
        || match (profile,&p.f_large_shares){(Some(_),None)=>false,(None,Some(v))=>v.len()!=len,_=>true}{return false;}
    // Sharing, transport and rebuilding use the same PPTB SHA-256 rule.
    if !crate::node::merkle::validate_batch(&p.mps){return false;}
    if let Some(profile)=profile {
        let batch=match public.root_vec.len().checked_sub(super::context::PPT_COIN_RESERVE){Some(b) if b>0=>b,_=>return false};
        for i in 0..len {
            let proof=&p.mps[i];
            if !proof.matches_leaf(source,n)||proof.root()!=public.root_vec[offset+i]
                ||BigUint::from_bytes_be(&p.nonces[i])>=*large
                ||proof.item()!=types::beacon::avss_commit_leaf_gf2(&p.secrets[i],&p.mask_shares[i],&p.nonces[i]){return false;}
        }
        return super::batch_degree_test::verify_values(public,&p.secrets,&p.mask_shares,offset,batch,source,n,f,profile);
    }
    let theta=Context::theta_from_commitment(public.round,public.origin,&public.root_vec,large);
    let binary=profile.and_then(|p|super::shamir::gf2_two_field::Gf2TwoFieldDealer::new(p,f+1,n).ok());
    let binary_theta=profile.map(|p|Context::theta_from_commitment_gf2(public.round,public.origin,&public.root_vec,p));
    let prime=super::shamir::two_field::TwoFieldDealer::new(small.clone(),large.clone(),f+1,n);
    for i in 0..len {
        let h=&public.degree_test_coeffs[offset+i];let proof=&p.mps[i];
        if h.len()!=f+1||!proof.matches_leaf(source,n)||proof.root()!=public.root_vec[offset+i]
            ||BigUint::from_bytes_be(&p.nonces[i])>=*large{return false;}
        let leaf=match profile {
            Some(profile)=>{
                let base=match Gf2Profile::new(profile.w_p,profile.w_p){Ok(v)=>v,Err(_)=>return false};
                if Gf2Element::from_bytes(base,p.secrets[i]).is_err(){return false;}
                let secret=match Gf2Element::from_bytes(profile,p.secrets[i]){Ok(v)=>v,Err(_)=>return false};
                let mask=match Gf2Element::from_bytes(profile,p.mask_shares[i]){Ok(v)=>v,Err(_)=>return false};
                let coefficients=match h.iter().map(|v|Gf2Element::from_bytes(profile,*v)).collect::<Result<Vec<_>,_>>(){Ok(v)=>v,Err(_)=>return false};
                if !binary.as_ref().unwrap().verify_share(source+1,&secret,&mask,&coefficients,binary_theta.as_ref().unwrap()){return false;}
                types::beacon::avss_commit_leaf_gf2(&p.secrets[i],&p.mask_shares[i],&p.nonces[i])
            }
            None=>{
                let secret=BigUint::from_bytes_be(&p.secrets[i]);let mask=BigUint::from_bytes_be(&p.mask_shares[i]);
                let lifted=p.f_large_shares.as_ref().unwrap()[i];let lifted_num=BigUint::from_bytes_be(&lifted);
                if secret>=*small||mask>=*large||lifted_num>=*large||&lifted_num%small!=secret{return false;}
                let coefficients:Vec<_>=h.iter().map(|v|BigUint::from_bytes_be(v)).collect();
                if coefficients.iter().any(|v|v>=large)||!prime.verify_share(source+1,&lifted_num,&mask,&coefficients,&theta){return false;}
                types::beacon::avss_commit_leaf(&p.secrets[i],&p.mask_shares[i],&lifted,&p.nonces[i])
            }
        };
        if proof.item()!=leaf{return false;}
    }true
}

impl Context {
    pub(crate) fn original_beacon_payload(&self,round:Round,dealer:Replica)->Option<AvssRecipientPayload> {
        if let Some(bytes)=self.avss_beacon_bytes.get(&(round,dealer)) {
            let p=super::batch_degree_test::decode_payload(bytes,self.gf2_profile,self.batch_size,0)?;
            let public=self.avss_secmsg_public.get(&(round,dealer))?;
            if validate_original(public,&p,0,self.batch_size,self.myid,self.num_nodes,self.num_faults,
                &self.secret_domain,&self.nonce_domain,self.gf2_profile,&self.hash_context){return Some(p);}return None;
        }
        let state=self.round_state.get(&round)?;
        if !state.avss_local_valid.contains(&dealer){return None;}
        let wss=state.node_secrets.get(&dealer)?;
        let p=AvssRecipientPayload::new(wss.secrets.clone(),wss.nonces.clone(),state.mask_shares.get(&dealer)?.clone(),
            if self.gf2_profile.is_none(){Some(state.f_large_shares.get(&dealer)?.clone())}else{None},wss.mps.clone());
        slice_payload(&p,0,self.batch_size)
    }

    #[async_recursion]
    pub(crate) async fn try_send_local_transform(&mut self,round:Round) {
        let state=match self.round_state.get(&round){Some(s) if !s.cleared=>s,_=>return};
        let dealers=match &state.acs_decided_set{Some(d)=>d.clone(),None=>return};
        let pipeline=self.share_pipeline.entry(round).or_default();
        if pipeline.sent||pipeline.matrix_inflight{return;}
        let mut input=Vec::with_capacity(dealers.len());
        for dealer in &dealers {
            if let Some(p)=self.original_beacon_payload(round,*dealer){input.push(p.secrets);}
            else if let Some(p)=self.awss_recovery.get(&(round,*dealer)).and_then(|s|s.local_shares.as_ref()) {
                if p.secrets.len()!=self.batch_size{return;}input.push(p.secrets.clone());
            }else{return;}
        }
        let state=self.round_state.get(&round).unwrap();let binary=state.gf2_super_inv_extractor.clone();
        let prime=state.super_inv_extractor.clone();let profile=self.gf2_profile;let batch=self.batch_size;
        self.share_pipeline.get_mut(&round).unwrap().matrix_inflight=true;
        let tx=self.share_tx.clone();
        tokio::spawn(async move{
            let result=tokio::task::spawn_blocking(move||->Result<Vec<Val>,String>{
                let mut values=Vec::new();
                for coin in 0..batch {
                    if let Some(profile)=profile {
                        let column=input.iter().map(|v|Gf2Element::from_bytes(profile,v[coin]).map_err(|e|e.to_string())).collect::<Result<Vec<_>,_>>()?;
                        for v in binary.as_ref().ok_or("missing matrix")?.transform_shares(&column)?{values.push(*v.as_bytes());}
                    }else{
                        let column=input.iter().map(|v|BigUint::from_bytes_be(&v[coin])).collect::<Vec<_>>();
                        for v in prime.as_ref().ok_or("missing matrix")?.transform_shares(&column)?{values.push(Context::pad_shares(v));}
                    }
                }Ok(values)
            }).await.map_err(|e|e.to_string()).and_then(|v|v);
            let _=tx.send(ShareCompletion::Transformed{round,dealers,values:result});
        });
    }

    #[async_recursion]
    pub(crate) async fn process_transformed_shares(&mut self,round:Round,dealers:Vec<Replica>,values:Vec<Val>,sender:Replica) {
        if sender>=self.num_nodes||round>self.max_rounds||dealers.len()<self.num_nodes-self.num_faults||dealers.len()>self.num_nodes
            ||dealers.iter().any(|d|*d>=self.num_nodes)||dealers.windows(2).any(|w|w[0]>=w[1])
            ||values.len()!=self.batch_size*(dealers.len()-self.num_faults)
            ||self.round_state.get(&round).map(|s|s.cleared).unwrap_or(false){return;}
        let field=self.beacon_oec_field();if values.iter().any(|v|!field.canonical(v)){return;}
        if let Some(selected)=self.round_state.get(&round).and_then(|s|s.acs_decided_set.as_ref()){if selected!=&dealers{return;}}
        let pipeline=self.share_pipeline.entry(round).or_default();
        if pipeline.points.contains_key(&sender){return;}
        pipeline.points.insert(sender,SharePacket{dealers,values:Arc::new(values)});pipeline.version+=1;
        self.try_decode_transformed(round).await;
    }

    pub(crate) fn beacon_oec_field(&self)->Field {match self.gf2_profile {
        Some(p)=>Field::Binary(Gf2Profile::new(p.w_p,p.w_p).expect("valid base field")),None=>Field::Prime(self.secret_domain.clone()),
    }}

    #[async_recursion]
    pub(crate) async fn try_decode_transformed(&mut self,round:Round) {
        let dealers=match self.round_state.get(&round){Some(s) if !s.cleared=>match &s.acs_decided_set{Some(d)=>d.clone(),None=>return},_=>return};
        let field=self.beacon_oec_field();let f=self.num_faults;let n=self.num_nodes;let coordinates=self.batch_size*(dealers.len()-f);
        let pipeline=self.share_pipeline.entry(round).or_default();
        if pipeline.decoding{return;}
        let points:BTreeMap<_,_>=pipeline.points.iter().filter(|(_,p)|p.dealers==dealers).map(|(s,p)|(*s,p.values.clone())).collect();
        if points.len()<2*f+1{return;}
        pipeline.decoded.resize(coordinates,None);
        if pipeline.decoded.iter().all(Option::is_some){return;}
        pipeline.decoding=true;let version=pipeline.version;let mut decoded=pipeline.decoded.clone();let mut cache=pipeline.cache.take().unwrap_or_default();
        let tx=self.share_tx.clone();
        tokio::spawn(async move{
            let result=tokio::task::spawn_blocking(move||{
                let mut errors=Vec::new();
                for coordinate in 0..coordinates {if decoded[coordinate].is_some(){continue;}
                    let input=points.iter().map(|(p,v)|(*p,v[coordinate].to_vec())).collect();
                    if let Some(poly)=oec::decode(&field,f,f,n,&input,&mut cache){errors.extend(poly.errors.iter().copied());decoded[coordinate]=Some(poly.at_zero());}
                }errors.sort_unstable();errors.dedup();(decoded,cache,errors)
            }).await;
            match result {
                Ok((decoded,cache,errors))=>{let _=tx.send(ShareCompletion::Decoded{round,version,decoded,cache,errors});}
                Err(error)=>{let _=tx.send(ShareCompletion::Failed{round,error:error.to_string()});}
            }
        });
    }

    #[async_recursion]
    pub(crate) async fn finalize_share_completion(&mut self,completion:ShareCompletion) {
        match completion {
            ShareCompletion::Failed{round,error}=>{
                if let Some(p)=self.share_pipeline.get_mut(&round){p.decoding=false;}
                log::error!("[PPT][OEC] worker failed round={}: {}; waiting for a retry, no output accepted",round,error);
            }
            ShareCompletion::Transformed{round,dealers,values}=>{
                let state=self.share_pipeline.entry(round).or_default();state.matrix_inflight=false;
                let values=match values{Ok(v)=>v,Err(e)=>{log::error!("[PPT][MATRIX] round={} failed: {}",round,e);return;}};
                if state.sent{return;}state.sent=true;
                log::info!("[PPT][LOCAL-MATRIX] node={} round={} dealers={:?} output_shares={}",self.myid,round,dealers,values.len());
                self.broadcast(wire::encode(&PptWire::TransformedShares{round,dealers:dealers.clone(),values:values.clone()}),round).await;
                self.process_transformed_shares(round,dealers,values,self.myid).await;
            }
            ShareCompletion::Decoded{round,version,decoded,cache,errors}=>{
                let pipeline=match self.share_pipeline.get_mut(&round){Some(p)=>p,None=>return};pipeline.decoding=false;pipeline.cache=Some(cache);pipeline.decoded=decoded;
                let changed=pipeline.version!=version;
                let state=match self.round_state.get_mut(&round){Some(s) if !s.cleared=>s,_=>return};
                let outputs=match &state.acs_decided_set{Some(d)=>d.len()-self.num_faults,None=>return};
                for coin in 0..self.batch_size {if state.recovered_coins.contains(&coin){continue;}
                    let values=pipeline.decoded[coin*outputs..(coin+1)*outputs].iter().cloned().collect::<Option<Vec<_>>>();
                    if let Some(values)=values{state.recovered_coins.insert(coin);state.pending_beacon_outputs.insert(coin,values);}
                }
                state.batch_reconstruction_complete=state.recovered_coins.len()==self.batch_size;
                if !errors.is_empty(){log::warn!("[PPT][OEC-PROVIDER] round={} rejected output points from {:?}",round,errors);}
                self.flush_pending_beacon_outputs(round,"share-level OEC").await;
                self.try_start_full_audit(round).await;
                if changed{self.try_decode_transformed(round).await;}
            }
        }
    }
}
