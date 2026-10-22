//! Post-ACS complaint/recovery for selected AWSS instances, using transferable
//! SecMsg evidence. Missing-data requests only replay the target's fragments.
//! Assists disclose provider messages only after a verified complaint proving
//! original-dealer misbehavior; a false request cannot expose honest secrets.
use std::collections::{BTreeMap, HashMap, HashSet};
use async_recursion::async_recursion;
use crypto::hash::Hash;
use crypto::gf2::{Gf2Element, Gf2Profile};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use types::{Replica, Round};
use types::beacon::{AvssRecipientPayload, CoinMsg};
use super::Context;
use super::shoup_smart::sec_msg_dst::{ForwardMessagePayload, SecMsgChannel, SecMsgDstAction};
use super::wire::{PptWire, ForwardTag};

#[derive(Debug, Clone)]
pub(crate) struct RecoveredAwssShares {
    pub secrets: Vec<types::beacon::Val>,
    pub masks: Vec<types::beacon::Val>,
    pub nonces: Vec<types::beacon::Val>,
    pub f_large: Option<Vec<types::beacon::Val>>,
    pub providers: Vec<Replica>,
    // The original assist payloads and key/cipher certificates are retained in
    // AwssRecoveryState. These derived values have NO original Merkle paths.
}

#[derive(Default)]
pub(crate) struct AwssRecoveryState {
    pub selected: bool,
    requested: bool,
    requests: HashSet<Replica>,
    replayed: HashSet<(Replica, SecMsgChannel)>,
    complaint_sent: bool,
    complaint: Option<(Replica, ForwardMessagePayload)>,
    report_sent: bool,
    assist_sent: bool,
    ack_sent: bool,
    pub recovered_peers: HashSet<Replica>,
    assists: BTreeMap<Replica, AvssRecipientPayload>,
    certificates: BTreeMap<Replica, ForwardMessagePayload>,
    channels: HashMap<Replica, (Option<super::shoup_smart::rel_msg_dst::ForwardPayload>,
                               Option<super::shoup_smart::rel_msg_dst::ForwardPayload>)>,
    pub local_shares: Option<RecoveredAwssShares>,
    pending: Vec<(PptWire, Replica)>,
}

impl AwssRecoveryState {
    pub(crate) fn has_complaint(&self) -> bool { self.complaint.is_some() }
}

fn pending_slot(message: &PptWire) -> (u8, Replica, u8) {
    match message {
        PptWire::AwssForward { source, tag, .. } => (0, *source, *tag as u8),
        PptWire::AwssChannelForward { source, channel, .. } => (1, *source, *channel as u8),
        PptWire::AwssRequest { recipient, .. } => (2, *recipient, 0),
        _ => (3, 0, 0),
    }
}

impl Context {
    pub(crate) fn awss_selected(&self, round: Round, dealer: Replica) -> bool {
        self.awss_recovery.get(&(round, dealer)).map(|state| state.selected).unwrap_or(false)
    }
    pub(crate) fn awss_root(&self, round: Round, dealer: Replica) -> Option<Hash> {
        let public = self.avss_secmsg_public.get(&(round, dealer))?;
        Some(crypto::hash::do_hash(&super::public_rbc::transcript(public).serialize_ctrbc()))
    }
    fn awss_happy(&self, round: Round, dealer: Replica, source: Replica, bytes: &[u8]) -> bool {
        let payload=match super::batch_degree_test::decode_payload(bytes,self.gf2_profile,self.batch_size,0){Some(p)=>p,None=>return false};
        let public=match self.avss_secmsg_public.get(&(round,dealer)){Some(p)=>p,None=>return false};
        super::share_pipeline::validate_original(public,&payload,0,self.batch_size,source,self.num_nodes,self.num_faults,
            &self.secret_domain,&self.nonce_domain,self.gf2_profile,&self.hash_context,self.batch_input_root(round,dealer).as_ref())
    }

    /// Out-of-order subprotocol data is processed only after public RBC fixed
    /// its exact key/cipher roots. One message per authenticated sender/type.
    pub(crate) fn defer_secmsg(&mut self, round: Round, dealer: Replica, message: CoinMsg, sender: Replica) -> bool {
        if sender >= self.num_nodes || dealer >= self.num_nodes { return true; }
        if self.avss_public_bundles.get(&(round, dealer)).and_then(|bundle| bundle.secmsg_roots).is_some() { return false; }
        if self.round_state.get(&round).map(|state| state.cleared).unwrap_or(false) { return true; }
        let pending = self.avss_secmsg_pending.entry((round, dealer)).or_default();
        let kind = std::mem::discriminant(&message);
        if !pending.iter().any(|(existing, peer)| *peer == sender && std::mem::discriminant(existing) == kind) {
            pending.push((message, sender));
        }
        true
    }

    #[async_recursion]
    pub(crate) async fn start_selected_awss_recovery(&mut self, round: Round, dealers: &[Replica]) {
        for &dealer in dealers {
            self.awss_recovery.entry((round, dealer)).or_default().selected = true;
            self.drive_awss_recovery(round, dealer).await;
            self.request_selected_reserve(round,dealer).await;
        }
    }

    #[async_recursion]
    pub(crate) async fn drive_awss_recovery(&mut self, round: Round, dealer: Replica) {
        if !self.awss_selected(round, dealer) { return; }
        let root = match self.awss_root(round, dealer) { Some(root) => root, None => return };
        let have_original = self.original_beacon_payload(round,dealer).is_some();
        let have_recovered = self.awss_recovery.get(&(round, dealer)).and_then(|state| state.local_shares.as_ref()).is_some();
        let already_owned = self.awss_recovery.get(&(round, dealer)).unwrap().ack_sent;
        if have_original || have_recovered || already_owned {
            let state = self.awss_recovery.get_mut(&(round, dealer)).unwrap();
            if !state.ack_sent {
                state.ack_sent = true;
                state.recovered_peers.insert(self.myid);
                self.broadcast(super::wire::encode(&PptWire::AwssRecovered { round, dealer, root }), round).await;
            }
        } else if !self.awss_recovery.get(&(round, dealer)).unwrap().requested {
            self.awss_recovery.get_mut(&(round, dealer)).unwrap().requested = true;
            self.broadcast(super::wire::encode(&PptWire::AwssRequest { round, dealer, root, recipient: self.myid }), round).await;
        }
        // Replay only this requester's own key/cipher fragments. The provider
        // cannot reveal its own secret-share plaintext in response to a request.
        let requesters: Vec<Replica> = self.awss_recovery.get(&(round, dealer)).unwrap().requests.iter().copied().collect();
        for recipient in requesters {
            let actions = self.avss_secmsg_state.get(&(round, dealer))
                .map(|state| state.replay_for_recipient(recipient)).unwrap_or_default();
            let mut fresh = Vec::new();
            for action in actions {
                if let SecMsgDstAction::SendEcho { channel, .. } = &action {
                    if self.awss_recovery.get_mut(&(round, dealer)).unwrap().replayed.insert((recipient, *channel)) { fresh.push(action); }
                }
            }
            if !fresh.is_empty() { self.dispatch_avss_secmsg_actions(round, dealer, fresh).await; }
        }
        // Both committed channels may be invalid (bottom) but still have a
        // complete proof. Never treat missing data alone as a provable complaint.
        if !have_original && !have_recovered && !already_owned && !self.awss_recovery.get(&(round, dealer)).unwrap().complaint_sent {
            let recipient = (self.myid + 1) % self.num_nodes;
            let proof = self.avss_secmsg_state.get(&(round, dealer)).and_then(|state|
                match state.prepare_message_forward_for(recipient).ok()? {
                    SecMsgDstAction::SendMessageForward { payload, .. } => Some(payload), _ => None,
                });
            if let Some(proof) = proof {
                let check = self.avss_secmsg_state.get(&(round, dealer)).unwrap().check_message_forward(self.myid, &proof);
                let unhappy = match check { Ok(None) => true, Ok(Some(ref bytes)) => !self.awss_happy(round, dealer, self.myid, bytes), Err(_) => false };
                if unhappy {
                    self.awss_recovery.get_mut(&(round, dealer)).unwrap().complaint_sent = true;
                    self.broadcast_awss_proof(round, dealer, root, self.myid, ForwardTag::Complaint, proof.clone()).await;
                    self.accept_awss_proof(round, dealer, root, self.myid, ForwardTag::Complaint, proof).await;
                }
            }
        }
        if have_original && !self.awss_recovery.get(&(round, dealer)).unwrap().assist_sent {
            if let Some((source, proof)) = self.awss_recovery.get(&(round, dealer)).unwrap().complaint.clone() {
                self.accept_awss_proof(round, dealer, root, source, ForwardTag::Report, proof).await;
            }
        }
        let pending = std::mem::take(&mut self.awss_recovery.get_mut(&(round, dealer)).unwrap().pending);
        for (message, sender) in pending { self.process_awss_wire(message, sender).await; }
        self.try_start_dealer_audit(round,dealer).await;
        self.release_awss_serving_if_safe(round, dealer);
    }

    #[async_recursion]
    async fn broadcast_awss_proof(&mut self, round: Round, dealer: Replica, root: Hash,
        source: Replica, tag: ForwardTag, proof: ForwardMessagePayload) {
        for recipient in 0..self.num_nodes {
            if recipient != self.myid {
                self.send_ppt_wire(recipient, round, PptWire::AwssForward {
                    round, dealer, root, source, recipient, tag, proof: proof.clone() }).await;
            }
        }
    }

    #[async_recursion]
    pub(crate) async fn process_awss_wire(&mut self, message: PptWire, sender: Replica) {
        let (round, dealer, root) = match &message {
            PptWire::AwssRequest { round, dealer, root, .. }
            | PptWire::AwssRecovered { round, dealer, root }
            | PptWire::AwssForward { round, dealer, root, .. }
            | PptWire::AwssChannelForward { round, dealer, root, .. } => (*round, *dealer, *root),
            _ => return,
        };
        if dealer >= self.num_nodes || sender >= self.num_nodes { return; }
        if self.awss_root(round, dealer).is_none()
            && self.round_state.get(&round).map(|state| state.cleared).unwrap_or(false) { return; }
        if self.awss_root(round, dealer) != Some(root) || !self.awss_selected(round, dealer) {
            // Cache reorderings, with per-authenticated-sender/type/source bounds.
            let pending = &mut self.awss_recovery.entry((round, dealer)).or_default().pending;
            let kind = pending_slot(&message);
            if !pending.iter().any(|(old, peer)| *peer == sender && pending_slot(old) == kind) {
                pending.push((message, sender));
            }
            return;
        }
        match message {
            PptWire::AwssRequest { recipient, .. } => {
                if recipient != sender || recipient == self.myid { return; }
                self.awss_recovery.get_mut(&(round, dealer)).unwrap().requests.insert(recipient);
                self.drive_awss_recovery(round, dealer).await;
            }
            PptWire::AwssRecovered { .. } => {
                self.awss_recovery.get_mut(&(round, dealer)).unwrap().recovered_peers.insert(sender);
                self.release_awss_serving_if_safe(round, dealer);
            }
            PptWire::AwssForward { source, recipient, tag, proof, .. } => {
                if source >= self.num_nodes || recipient != self.myid || (tag != ForwardTag::Report && source != sender) { return; }
                self.accept_awss_proof(round, dealer, root, source, tag, proof).await;
            }
            PptWire::AwssChannelForward { source, recipient, channel, proof, .. } => {
                if source != sender || recipient != self.myid { return; }
                // Single-channel forwards can only be assists after a verified
                // complaint. The combined proof is checked before decoding.
                if self.awss_recovery.get(&(round, dealer)).unwrap().complaint.is_none() {
                    let message = PptWire::AwssChannelForward { round, dealer, root, source, recipient, channel, proof };
                    let pending = &mut self.awss_recovery.get_mut(&(round, dealer)).unwrap().pending;
                    if !pending.iter().any(|(old, peer)| *peer == sender && pending_slot(old) == pending_slot(&message)) {
                        pending.push((message, sender));
                    }
                    return;
                }
                let pair = self.awss_recovery.get_mut(&(round, dealer)).unwrap().channels.entry(source).or_default();
                match channel { SecMsgChannel::Key => pair.0 = Some(proof), SecMsgChannel::Cipher => pair.1 = Some(proof) }
                if let (Some(key), Some(cipher)) = (&pair.0, &pair.1) {
                    let proof = ForwardMessagePayload { key_forward: key.clone(), cipher_forward: cipher.clone() };
                    self.accept_awss_proof(round, dealer, root, source, ForwardTag::Assist, proof).await;
                }
            }
            _ => {}
        }
    }

    #[async_recursion]
    pub(crate) async fn accept_awss_proof(&mut self, round: Round, dealer: Replica, root: Hash,
        source: Replica, tag: ForwardTag, proof: ForwardMessagePayload) {
        if !self.awss_selected(round, dealer) || self.awss_root(round, dealer) != Some(root) { return; }
        let check = self.get_or_init_avss_secmsg(round, dealer).check_message_forward(source, &proof);
        let bytes = match check {
            Ok(value) => value,
            Err(reason) => { log::warn!("[PPT][AWSS] invalid provider evidence round={} dealer={} source={}: {:?}", round, dealer, source, reason); return; }
        };
        let happy = bytes.as_ref().map(|bytes| self.awss_happy(round, dealer, source, bytes)).unwrap_or(false);
        match tag {
            ForwardTag::Complaint | ForwardTag::Report => {
                if happy { return; }
                let state = self.awss_recovery.get_mut(&(round, dealer)).unwrap();
                if state.complaint.is_none() { state.complaint = Some((source, proof.clone())); }
                // Evidence is public; membership and the decided set stay fixed.
                self.suspected_dealers.insert(dealer);
                if !self.awss_recovery.get(&(round, dealer)).unwrap().report_sent {
                    self.awss_recovery.get_mut(&(round, dealer)).unwrap().report_sent = true;
                    self.broadcast_awss_proof(round, dealer, root, source, ForwardTag::Report, proof).await;
                }
                let own_happy = self.round_state.get(&round).map(|state| state.avss_local_valid.contains(&dealer)).unwrap_or(false)
                    || self.avss_secmsg_state.get(&(round, dealer)).and_then(|state| state.delivered_message())
                        .map(|bytes| self.awss_happy(round, dealer, self.myid, bytes)).unwrap_or(false);
                if own_happy && !self.awss_recovery.get(&(round, dealer)).unwrap().assist_sent {
                    let recipient = (self.myid + 1) % self.num_nodes;
                    if let Some(SecMsgDstAction::SendMessageForward { payload, .. }) =
                        self.avss_secmsg_state.get(&(round, dealer)).and_then(|state| state.prepare_message_forward_for(recipient).ok()) {
                        self.awss_recovery.get_mut(&(round,dealer)).unwrap().assist_sent=true;
                        self.broadcast_awss_proof(round, dealer, root, self.myid, ForwardTag::Assist, payload.clone()).await;
                        self.accept_awss_proof(round, dealer, root, self.myid, ForwardTag::Assist, payload).await;
                    }
                }
                self.note_verified_dealer_fault(dealer).await;
                self.recover_awss_local_share(round, dealer).await;
                // Recovery success drives the ACK/transform itself. If an assist
                // proof is not ready, wait for a new transport event rather than
                // recursively re-entering the same report with unchanged state.
                self.try_start_dealer_audit(round,dealer).await;
            }
            ForwardTag::Assist => {
                if !happy { return; }
                let payload = match bytes.and_then(|bytes| super::batch_degree_test::decode_payload(&bytes,self.gf2_profile,self.batch_size,0)) { Some(payload) => payload, None => return };
                let state = self.awss_recovery.get_mut(&(round, dealer)).unwrap();
                state.assists.entry(source).or_insert(payload);
                state.certificates.entry(source).or_insert(proof);
                // An assist is buffered across report/assist reordering. It
                // cannot establish a complaint or trigger disclosure itself.
                if state.complaint.is_some() { self.recover_awss_local_share(round, dealer).await; }
            }
        }
    }

    /// Retain original transport rows/public roots for delayed, valid complaints.
    /// Without a retirement certificate, ACKs alone cannot prove that no delayed
    /// complaint exists. Release derived work only; serving evidence stays live.
    pub(crate) fn release_awss_serving_if_safe(&mut self,round:Round,dealer:Replica) {
        let cleared=self.round_state.get(&round).map(|s|s.cleared).unwrap_or(false);
        if let Some(state)=self.awss_recovery.get_mut(&(round,dealer)) {
            if cleared && state.recovered_peers.len()==self.num_nodes {
                state.local_shares=None;state.assists.clear();
            }
        }
    }

}

fn prime_weights(providers: &[Replica], target: Replica, prime: &BigUint) -> Vec<BigUint> {
    let x = BigUint::from((target+1) as u64);
    providers.iter().enumerate().map(|(index, provider)| {
        let xi = BigUint::from((provider+1) as u64);
        let mut numerator = BigUint::one(); let mut denominator = BigUint::one();
        for (other, peer) in providers.iter().enumerate() {
            if index != other {
                let xj = BigUint::from((peer+1) as u64);
                numerator = numerator * (&x + prime - &xj) % prime;
                denominator = denominator * (&xi + prime - &xj) % prime;
            }
        }
        numerator * denominator.modpow(&(prime-BigUint::from(2u8)), prime) % prime
    }).collect()
}

fn prime_apply(weights: &[BigUint], values: &[types::beacon::Val], prime: &BigUint) -> types::beacon::Val {
    let result = weights.iter().zip(values).fold(BigUint::zero(), |sum, (weight, value)|
        (sum + weight * BigUint::from_bytes_be(value)) % prime);
    Context::pad_shares(result)
}

fn gf2_weights(profile: Gf2Profile, providers: &[Replica], target: Replica) -> Result<Vec<Gf2Element>, String> {
    let small = Gf2Profile::new(profile.w_p, profile.w_p).map_err(|error| error.to_string())?;
    let x = super::shamir::gf2_two_field::small_field_point(small, target+1);
    providers.iter().enumerate().map(|(index, provider)| {
        let xi = super::shamir::gf2_two_field::small_field_point(small, provider+1);
        let mut numerator = Gf2Element::one(small); let mut denominator = Gf2Element::one(small);
        for (other, peer) in providers.iter().enumerate() {
            if index != other {
                let xj = super::shamir::gf2_two_field::small_field_point(small, peer+1);
                numerator = numerator.mul(&x.add(&xj)); denominator = denominator.mul(&xi.add(&xj));
            }
        }
        if denominator.is_zero() { return Err("duplicate recovery point".to_string()); }
        let coefficient = numerator.mul(&denominator.inv());
        Gf2Element::from_bytes(profile, *coefficient.as_bytes()).map_err(|error| error.to_string())
    }).collect()
}

fn gf2_apply(profile: Gf2Profile, weights: &[Gf2Element], values: &[types::beacon::Val]) -> Result<types::beacon::Val, String> {
    let mut result = Gf2Element::zero(profile);
    for (weight, value) in weights.iter().zip(values) {
        let value = Gf2Element::from_bytes(profile, *value).map_err(|error| error.to_string())?;
        result = result.add(&value.mul_small(weight));
    }
    Ok(*result.as_bytes())
}

impl Context {
    #[async_recursion]
    async fn recover_awss_local_share(&mut self, round: Round, dealer: Replica) {
        if self.awss_recovery.get(&(round, dealer)).map(|state| state.ack_sent).unwrap_or(false) { return; }
        let state = match self.awss_recovery.get(&(round, dealer)) { Some(state) => state, None => return };
        if state.complaint.is_none() || state.local_shares.is_some() || state.assists.len() < self.num_faults+1 { return; }
        let chosen: Vec<(Replica, AvssRecipientPayload)> = state.assists.iter().take(self.num_faults+1)
            .map(|(provider, payload)| (*provider, payload.clone())).collect();
        let providers: Vec<Replica> = chosen.iter().map(|(provider, _)| *provider).collect();
        // Compute interpolation coefficients once per recipient/provider set,
        // preserving small-field work and mul_small for the entire batch.
        let binary_weights = match self.gf2_profile {
            Some(profile) => match gf2_weights(profile, &providers, self.myid) { Ok(weights) => Some(weights), Err(_) => return },
            None => None,
        };
        let secret_weights = if self.gf2_profile.is_none() { prime_weights(&providers, self.myid, &self.secret_domain) } else { Vec::new() };
        let mask_weights = if self.gf2_profile.is_none() { prime_weights(&providers, self.myid, &self.nonce_domain) } else { Vec::new() };
        let total = self.batch_size;
        let mut secrets = Vec::with_capacity(total); let mut masks = Vec::with_capacity(total);
        let nonce_weights=prime_weights(&providers,self.myid,&self.nonce_domain);
        let mut nonces=Vec::with_capacity(total);
        let mut f_large = self.gf2_profile.is_none().then(|| Vec::with_capacity(total));
        let shared_mask=if let Some(profile)=self.gf2_profile {
            let points:Vec<_>=chosen.iter().map(|(_,p)|p.mask_shares[0]).collect();
            match gf2_apply(profile,binary_weights.as_ref().unwrap(),&points){Ok(v)=>Some(v),Err(_)=>return}
        }else{None};
        for coin in 0..total {
            let secret_points: Vec<_> = chosen.iter().map(|(_, payload)| payload.secrets[coin]).collect();
            let mask_points: Vec<_> = chosen.iter().map(|(_, payload)| payload.mask_shares[coin]).collect();
            let nonce_points:Vec<_>=chosen.iter().map(|(_,p)|p.nonces[coin]).collect();
            nonces.push(prime_apply(&nonce_weights,&nonce_points,&self.nonce_domain));
            match self.gf2_profile {
                Some(profile) => {
                    let secret = match gf2_apply(profile, binary_weights.as_ref().unwrap(), &secret_points) { Ok(value) => value, Err(_) => return };
                    let mask = shared_mask.expect("one recovered GF2 main mask");
                    secrets.push(secret); masks.push(mask);
                }
                None => {
                    secrets.push(prime_apply(&secret_weights, &secret_points, &self.secret_domain));
                    masks.push(prime_apply(&mask_weights, &mask_points, &self.nonce_domain));
                    let points: Vec<_> = chosen.iter().map(|(_, payload)| payload.f_large_shares.as_ref().unwrap()[coin]).collect();
                    f_large.as_mut().unwrap().push(prime_apply(&mask_weights, &points, &self.nonce_domain));
                }
            }
        }
        // Recheck the derived share against the agreed public h. The original
        // per-point Merkle authentication stays on the retained assist inputs.
        let public = match self.avss_secmsg_public.get(&(round, dealer)) { Some(public) => public, None => return };
        match self.gf2_profile {
            Some(profile) => {
                if !super::batch_degree_test::verify_values(public,&secrets,&masks,0,total,self.myid,
                    self.num_nodes,self.num_faults,profile,self.batch_input_root(round,dealer).as_ref()){return;}
            }
            None => {
                let verifier = super::shamir::two_field::TwoFieldDealer::new(self.secret_domain.clone(), self.nonce_domain.clone(), self.num_faults+1, self.num_nodes);
                let theta = Context::theta_from_commitment(round, dealer, &public.root_vec, &self.nonce_domain);
                for coin in 0..total {
                    let coefficients: Vec<_> = public.degree_test_coeffs[coin].iter().map(|value| BigUint::from_bytes_be(value)).collect();
                    if !verifier.verify_share(self.myid+1, &BigUint::from_bytes_be(&f_large.as_ref().unwrap()[coin]),
                        &BigUint::from_bytes_be(&masks[coin]), &coefficients, &theta) { return; }
                }
            }
        }
        self.awss_recovery.get_mut(&(round, dealer)).unwrap().local_shares = Some(RecoveredAwssShares {
            secrets, masks, nonces, f_large, providers: chosen.iter().map(|(provider, _)| *provider).collect() });
        log::info!("[PPT][AWSS-RECOVERED] node={} round={} dealer={} certified providers={:?}", self.myid, round, dealer,
            chosen.iter().map(|(provider, _)| *provider).collect::<Vec<_>>());
        self.try_send_local_transform(round).await;
        self.drive_awss_recovery(round, dealer).await;
    }
}
