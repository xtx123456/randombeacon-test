//! PPT share-level extraction followed by polynomial OEC.
use std::collections::BTreeMap;
use async_recursion::async_recursion;
use crypto::aes_hash::HashState;
use crypto::gf2::{Gf2Element,Gf2Profile};
use num_bigint::BigUint;
use types::{Replica,Round};
use types::beacon::{AvssPublicCommitMsg,AvssRecipientPayload,Val};
use super::{Context,oec::{self,Field,OecCache},wire::{self,PptWire}};

#[derive(Clone)]
struct RecPacket { context:crypto::hash::Hash, points:BTreeMap<usize,Val> }
#[derive(Default)]
pub(crate) struct SharePipeline {
    matrix_inflight:bool,sent:bool,
    inner:BTreeMap<Replica,RecPacket>,outer:BTreeMap<Replica,RecPacket>,
    version:u64,attempted:Option<u64>,decoding:bool,
    inner_cache:Option<OecCache>,outer_cache:Option<OecCache>,
    owned:Vec<Option<Val>>,decoded:Vec<Option<Vec<u8>>>,
}
pub(crate) enum ShareCompletion {
    Transformed {round:Round,dealers:Vec<Replica>,packets:Result<Vec<Vec<Val>>,String>},
    Decoded {round:Round,version:u64,owned:Vec<Option<Val>>,decoded:Vec<Option<Vec<u8>>>,
        inner_cache:OecCache,outer_cache:OecCache,errors:Vec<Replica>},
    Failed {round:Round,error:String},
}

pub(crate) fn slice_payload(p:&AvssRecipientPayload,start:usize,len:usize,batch:usize)->Option<AvssRecipientPayload> {
    let end=start.checked_add(len)?;
    let proofs=if p.mps.len()==p.secrets.len(){p.mps.get(start..end)?.to_vec()}
        else if p.secrets.len()==batch&&p.mps.is_empty()&&start==0&&len==batch{Vec::new()}
        else if p.secrets.len()==batch+super::context::PPT_COIN_RESERVE&&p.mps.len()==super::context::PPT_COIN_RESERVE {
            if start==0&&len==batch{Vec::new()}
            else if start==batch&&len==super::context::PPT_COIN_RESERVE{p.mps.clone()}
            else{return None;}
        }else{return None;};
    Some(AvssRecipientPayload::new(p.secrets.get(start..end)?.to_vec(),p.nonces.get(start..end)?.to_vec(),
        p.mask_shares.get(start..end)?.to_vec(),match &p.f_large_shares{Some(v)=>Some(v.get(start..end)?.to_vec()),None=>None},proofs))
}
pub(crate) fn join_payloads(mut a:AvssRecipientPayload,b:AvssRecipientPayload)->Option<AvssRecipientPayload> {
    a.secrets.extend(b.secrets);a.nonces.extend(b.nonces);a.mask_shares.extend(b.mask_shares);a.mps.extend(b.mps);
    match (&mut a.f_large_shares,b.f_large_shares){(Some(a),Some(b))=>a.extend(b),(None,None)=>{},_=>return None,}Some(a)
}

/// A main_binding is supplied ONLY for SecMsg-authenticated plaintexts or
/// verified Forward/audit reconstructions. It replaces main coin paths, never
/// input authentication. Reserves and Lite comparisons retain their paths.
pub(crate) fn validate_original(public:&AvssPublicCommitMsg,p:&AvssRecipientPayload,
    offset:usize,len:usize,source:Replica,n:usize,f:usize,small:&BigUint,large:&BigUint,
    profile:Option<Gf2Profile>,_hash:&HashState,main_binding:Option<&crypto::hash::Hash>)->bool {
    let batch=public.root_vec.len().checked_sub(super::context::PPT_COIN_RESERVE);
    let expected_proofs=if main_binding.is_some()&&offset==0 {
        match batch{Some(batch) if len==batch=>0,
            Some(batch) if len==batch+super::context::PPT_COIN_RESERVE=>super::context::PPT_COIN_RESERVE,_=>return false}
    }else{len};
    if (main_binding.is_some()&&profile.is_none())||source>=n||p.secrets.len()!=len||p.nonces.len()!=len||p.mask_shares.len()!=len||p.mps.len()!=expected_proofs
        ||offset.checked_add(len).map(|end|end>public.root_vec.len()
            ||(profile.is_none()&&end>public.degree_test_coeffs.len())).unwrap_or(true)
        || match (profile,&p.f_large_shares){(Some(_),None)=>false,(None,Some(v))=>v.len()!=len,_=>true}{return false;}
    // Sharing, transport and rebuilding use the same PPTB SHA-256 rule.
    if !p.mps.is_empty()&&!crate::node::merkle::validate_batch(&p.mps){return false;}
    if let Some(profile)=profile {
        let batch=match batch{Some(b) if b>0=>b,_=>return false};
        for i in 0..len {
            if BigUint::from_bytes_be(&p.nonces[i])>=*large{return false;}
            if main_binding.is_some()&&offset+i<batch{continue;}
            let index=if main_binding.is_some()&&offset==0{i-batch}else{i};
            let proof=&p.mps[index];
            if !proof.matches_leaf(source,n)||proof.root()!=public.root_vec[offset+i]
                ||proof.item()!=types::beacon::avss_commit_leaf_gf2(&p.secrets[i],&p.mask_shares[i],&p.nonces[i]){return false;}
        }
        return super::batch_degree_test::verify_values(public,&p.secrets,&p.mask_shares,offset,batch,source,n,f,profile,main_binding);
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
        let binding=self.batch_input_root(round,dealer);
        if binding.is_some()&&!self.has_secmsg_batch_delivery(round,dealer){return None;}
        if let Some(bytes)=self.avss_beacon_bytes.get(&(round,dealer)) {
            let p=super::batch_degree_test::decode_payload(bytes,self.gf2_profile,self.batch_size,0)?;
            let public=self.avss_secmsg_public.get(&(round,dealer))?;
            if validate_original(public,&p,0,self.batch_size,self.myid,self.num_nodes,self.num_faults,
                &self.secret_domain,&self.nonce_domain,self.gf2_profile,&self.hash_context,binding.as_ref()){return Some(p);}return None;
        }
        let state=self.round_state.get(&round)?;
        if !state.avss_local_valid.contains(&dealer){return None;}
        let wss=state.node_secrets.get(&dealer)?;
        let p=AvssRecipientPayload::new(wss.secrets.clone(),wss.nonces.clone(),state.mask_shares.get(&dealer)?.clone(),
            if self.gf2_profile.is_none(){Some(state.f_large_shares.get(&dealer)?.clone())}else{None},wss.mps.clone());
        slice_payload(&p,0,self.batch_size,self.batch_size)
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
        let tx=self.share_tx.clone();let field=self.beacon_oec_field();let n=self.num_nodes;let f=self.num_faults;
        tokio::spawn(async move{
            let result=tokio::task::spawn_blocking(move||->Result<Vec<Vec<Val>>,String>{
                let mut values=Vec::new();
                for coin in 0..batch {
                    if let Some(profile)=profile {
                        let column=input.iter().map(|v|Gf2Element::from_bytes(profile,v[coin]).map_err(|e|e.to_string())).collect::<Result<Vec<_>,_>>()?;
                        for v in binary.as_ref().ok_or("missing matrix")?.transform_shares(&column)?{values.push(*v.as_bytes());}
                    }else{
                        let column=input.iter().map(|v|BigUint::from_bytes_be(&v[coin])).collect::<Vec<_>>();
                        for v in prime.as_ref().ok_or("missing matrix")?.transform_shares(&column)?{values.push(Context::pad_shares(v));}
                    }
                }
                let k=f+1;
                // At n=3f+1, n-k=2f: exactly f correctable errors.
                if n<3*f+1 || n-k<2*f || !field.distinct_points(n){return Err("invalid BatchRec point/error budget".into());}
                let blocks=(values.len()+k-1)/k;let mut packets=vec![Vec::with_capacity(blocks);n];
                for block in values.chunks(k) {
                    let mut coefficients=block.to_vec();coefficients.resize(k,[0u8;32]);
                    let encoded=field.encode_block(&coefficients,n).ok_or("noncanonical BatchRec coefficient")?;
                    for (recipient,value) in encoded.into_iter().enumerate(){packets[recipient].push(value);}
                }
                Ok(packets)
            }).await.map_err(|e|e.to_string()).and_then(|v|v);
            let _=tx.send(ShareCompletion::Transformed{round,dealers,packets:result});
        });
    }


    fn reconstruction_context(&self,round:Round)->Option<(crypto::hash::Hash,usize)> {
        let dealers=self.round_state.get(&round)?.acs_decided_set.as_ref()?;
        let count=self.batch_size.checked_mul(dealers.len().checked_sub(self.num_faults)?)?;
        let bytes=bincode::serialize(&(b"PPTB_BATCHREC_V1",round,dealers,self.batch_size,self.num_nodes,self.num_faults,
            self.secret_domain.to_bytes_be(),self.gf2_profile.map(|p|(p.w_p,p.w_q)))).ok()?;
        Some((crypto::hash::do_hash(&bytes),count))
    }

    pub(crate) fn beacon_oec_field(&self)->Field {match self.gf2_profile {
        Some(p)=>Field::Binary(Gf2Profile::new(p.w_p,p.w_p).expect("valid base field")),None=>Field::Prime(self.secret_domain.clone()),
    }}

    #[async_recursion]
    pub(crate) async fn process_batch_rec(&mut self,round:Round,context:crypto::hash::Hash,stage:u8,values:Vec<(usize,Val)>,sender:Replica) {
        if sender>=self.num_nodes || stage>1 || round>self.max_rounds
            || self.round_state.get(&round).map(|s|s.cleared).unwrap_or(false){return;}
        let k=self.num_faults+1;
        let max_coordinates=match self.batch_size.checked_mul(self.num_nodes-self.num_faults){Some(n)=>n,None=>return};
        let max_blocks=(max_coordinates+k-1)/k;
        if values.is_empty() || values.len()>max_blocks || values.iter().any(|(block,_)|*block>=max_blocks){return;}
        let field=self.beacon_oec_field();if values.iter().any(|(_,v)|!field.canonical(v)){return;}
        if let Some((expected,count))=self.reconstruction_context(round) {
            if context!=expected || values.iter().any(|(block,_)|*block>=(count+k-1)/k){return;}
        }
        let pipeline=self.share_pipeline.entry(round).or_default();
        let map=if stage==0 {&mut pipeline.inner}else{&mut pipeline.outer};
        let packet=map.entry(sender).or_insert_with(||RecPacket{context,points:BTreeMap::new()});
        if packet.context!=context{return;}
        let mut changed=false;
        for (block,value) in values {if !packet.points.contains_key(&block){packet.points.insert(block,value);changed=true;}}
        if changed {pipeline.version+=1;self.try_decode_transformed(round).await;}
    }

    #[async_recursion]
    pub(crate) async fn try_decode_transformed(&mut self,round:Round) {
        if self.round_state.get(&round).map(|s|s.cleared).unwrap_or(true){return;}
        let (context,coordinates)=match self.reconstruction_context(round){Some(v)=>v,None=>return};
        let field=self.beacon_oec_field();let f=self.num_faults;let n=self.num_nodes;let k=f+1;let blocks=(coordinates+k-1)/k;
        let pipeline=self.share_pipeline.entry(round).or_default();
        if pipeline.decoding || pipeline.attempted==Some(pipeline.version){return;}
        let collect=|map:&BTreeMap<Replica,RecPacket>|map.iter().filter(|(_,p)|p.context==context)
            .map(|(provider,p)|(*provider,p.points.clone())).collect::<BTreeMap<_,_>>();
        let inner=collect(&pipeline.inner);let outer=collect(&pipeline.outer);
        if inner.len()<2*f+1 && outer.len()<k+f{return;}
        pipeline.owned.resize(blocks,None);pipeline.decoded.resize(coordinates,None);
        pipeline.decoding=true;pipeline.attempted=Some(pipeline.version);let version=pipeline.version;
        let mut owned=pipeline.owned.clone();let mut decoded=pipeline.decoded.clone();
        let mut inner_cache=pipeline.inner_cache.take().unwrap_or_default();let mut outer_cache=pipeline.outer_cache.take().unwrap_or_default();
        let tx=self.share_tx.clone();
        tokio::spawn(async move{
            let result=tokio::task::spawn_blocking(move||{
                let mut errors=Vec::new();
                for block in 0..blocks {
                    if owned[block].is_none() {
                        let points=inner.iter().filter_map(|(p,rows)|rows.get(&block).map(|v|(*p,v.to_vec()))).collect();
                        if let Some(poly)=oec::decode(&field,f,f,n,&points,&mut inner_cache){
                            owned[block]=oec::val(&poly.at_zero());errors.extend(poly.errors);
                        }
                    }
                    let start=block*k;let end=(start+k).min(coordinates);
                    if decoded[start..end].iter().all(Option::is_some){continue;}
                    let points=outer.iter().filter_map(|(p,rows)|rows.get(&block).map(|v|(*p,v.to_vec()))).collect();
                    if let Some(poly)=oec::decode(&field,k-1,f,n,&points,&mut outer_cache){
                        let coefficients=poly.coefficients();
                        for (offset,value) in coefficients.into_iter().take(end-start).enumerate(){decoded[start+offset]=Some(value);}
                        errors.extend(poly.errors);
                    }
                }
                errors.sort_unstable();errors.dedup();(owned,decoded,inner_cache,outer_cache,errors)
            }).await;
            match result {
                Ok((owned,decoded,inner_cache,outer_cache,errors))=>{let _=tx.send(ShareCompletion::Decoded{round,version,owned,decoded,inner_cache,outer_cache,errors});}
                Err(error)=>{let _=tx.send(ShareCompletion::Failed{round,error:error.to_string()});}
            }
        });
    }

    #[async_recursion]
    async fn emit_decoded_batch(&mut self,round:Round) {
        let pipeline=match self.share_pipeline.get(&round){Some(p)=>p,None=>return};
        // A fast node may decode using Byzantine owners that later withhold from
        // slow peers. Finish ALL our own first/second-stage duties before release.
        if !pipeline.sent || pipeline.owned.is_empty() || pipeline.owned.iter().any(Option::is_none){return;}
        let state=match self.round_state.get_mut(&round){Some(s) if !s.cleared=>s,_=>return};
        let outputs=match &state.acs_decided_set{Some(d)=>d.len()-self.num_faults,None=>return};
        for coin in 0..self.batch_size {
            if state.recovered_coins.contains(&coin){continue;}
            let values=pipeline.decoded[coin*outputs..(coin+1)*outputs].iter().cloned().collect::<Option<Vec<_>>>();
            if let Some(values)=values {state.recovered_coins.insert(coin);state.pending_beacon_outputs.insert(coin,values);}
        }
        state.batch_reconstruction_complete=state.recovered_coins.len()==self.batch_size;
        self.flush_pending_beacon_outputs(round,"two-layer BatchRec").await;
    }

    #[async_recursion]
    pub(crate) async fn finalize_share_completion(&mut self,completion:ShareCompletion) {
        match completion {
            ShareCompletion::Failed{round,error}=>{
                if let Some(p)=self.share_pipeline.get_mut(&round){p.decoding=false;p.attempted=None;}
                log::error!("[PPT][BATCHREC] worker failed round={}: {}",round,error);
            }
            ShareCompletion::Transformed{round,dealers,packets}=>{
                let (context,_)=match self.reconstruction_context(round){Some(v)=>v,None=>return};
                if self.round_state.get(&round).and_then(|s|s.acs_decided_set.as_ref())!=Some(&dealers){return;}
                let state=self.share_pipeline.entry(round).or_default();state.matrix_inflight=false;
                let packets=match packets {Ok(v)=>v,Err(e)=>{log::error!("[PPT][MATRIX] round={} failed: {}",round,e);return;}};
                if state.sent{return;}state.sent=true;
                for (recipient,row) in packets.into_iter().enumerate() {
                    let values=row.into_iter().enumerate().collect();
                    self.send_ppt_wire(recipient,round,PptWire::BatchRec{round,context,stage:0,values}).await;
                }
                self.try_decode_transformed(round).await;
                self.emit_decoded_batch(round).await;
            }
            ShareCompletion::Decoded{round,version,owned,decoded,inner_cache,outer_cache,errors}=>{
                let (context,_)=match self.reconstruction_context(round){Some(v)=>v,None=>return};
                let pipeline=match self.share_pipeline.get_mut(&round){Some(p)=>p,None=>return};
                let fresh:Vec<_>=owned.iter().enumerate().filter_map(|(block,value)|
                    if pipeline.owned.get(block).and_then(|v|v.as_ref()).is_none(){value.map(|v|(block,v))}else{None}).collect();
                pipeline.decoding=false;pipeline.inner_cache=Some(inner_cache);pipeline.outer_cache=Some(outer_cache);
                pipeline.owned=owned;pipeline.decoded=decoded;
                if !errors.is_empty(){log::warn!("[PPT][BATCHREC-PROVIDER] round={} errors={:?} (not dealer evidence)",round,errors);}
                if !fresh.is_empty() {
                    self.broadcast(wire::encode(&PptWire::BatchRec{round,context,stage:1,values:fresh.clone()}),round).await;
                    self.process_batch_rec(round,context,1,fresh,self.myid).await;
                }
                // Including arrivals during the worker and our own new outer points.
                if self.share_pipeline.get(&round).map(|p|p.version!=version).unwrap_or(false){self.try_decode_transformed(round).await;}
                self.emit_decoded_batch(round).await;
            }
        }
    }
}
