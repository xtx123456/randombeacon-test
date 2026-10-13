//! Polynomial online error correction; independent of transport RS erasures.
//!
//! For degree d and at most f faulty providers, accept a candidate only after
//! d+f+1 DISTINCT points agree with it. At least d+1 of those points are honest,
//! so the candidate is the honest polynomial. With e received errors this needs
//! d+f+1+e arrivals, at most n=3f+1 when d=f. Missing points remain erasures;
//! failed decoding never produces an output. Berlekamp-Welch is used only when
//! the cached interpolation fast path fails its support check.

use std::collections::{BTreeMap, HashMap};
use crypto::gf2::{Gf2Element, Gf2Profile};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use types::Replica;

#[derive(Clone, Debug)]
pub(crate) enum Field { Prime(BigUint), Binary(Gf2Profile) }

#[derive(Clone, Debug)]
enum Scalar { Prime(BigUint), Binary(Gf2Element) }

impl Field {
    fn zero(&self) -> Scalar { match self { Self::Prime(_) => Scalar::Prime(BigUint::zero()), Self::Binary(p) => Scalar::Binary(Gf2Element::zero(*p)) } }
    fn one(&self) -> Scalar { match self { Self::Prime(_) => Scalar::Prime(BigUint::one()), Self::Binary(p) => Scalar::Binary(Gf2Element::one(*p)) } }
    fn point(&self, provider: Replica) -> Scalar { match self {
        Self::Prime(p) => Scalar::Prime(BigUint::from((provider+1) as u64) % p),
        Self::Binary(p) => Scalar::Binary(super::shamir::gf2_two_field::small_field_point(*p, provider+1)),
    } }
    fn parse(&self, bytes: &[u8]) -> Option<Scalar> { match self {
        Self::Prime(p) => { let v=BigUint::from_bytes_be(bytes); if &v<p { Some(Scalar::Prime(v)) } else { None } },
        Self::Binary(p) => { if bytes.len()!=32 { return None; } let mut v=[0u8;32]; v.copy_from_slice(bytes); Gf2Element::from_bytes(*p,v).ok().map(Scalar::Binary) },
    } }
    fn bytes(&self, v: &Scalar) -> Vec<u8> { match (self,v) {
        (Self::Prime(p),Scalar::Prime(v)) => { let width=((p.bits()+7)/8) as usize; let bytes=v.to_bytes_be(); let mut out=vec![0; width]; out[width-bytes.len()..].copy_from_slice(&bytes); out },
        (_,Scalar::Binary(v)) => v.as_bytes().to_vec(), _ => unreachable!(),
    } }
    fn add(&self,a:&Scalar,b:&Scalar)->Scalar { match (self,a,b) {
        (Self::Prime(p),Scalar::Prime(a),Scalar::Prime(b))=>Scalar::Prime((a+b)%p),
        (_,Scalar::Binary(a),Scalar::Binary(b))=>Scalar::Binary(a.add(b)), _=>unreachable!(),
    } }
    fn sub(&self,a:&Scalar,b:&Scalar)->Scalar { match (self,a,b) {
        (Self::Prime(p),Scalar::Prime(a),Scalar::Prime(b))=>Scalar::Prime((a+p-b)%p),
        (_,Scalar::Binary(a),Scalar::Binary(b))=>Scalar::Binary(a.add(b)), _=>unreachable!(),
    } }
    fn mul(&self,a:&Scalar,b:&Scalar)->Scalar { match (self,a,b) {
        (Self::Prime(p),Scalar::Prime(a),Scalar::Prime(b))=>Scalar::Prime(a*b%p),
        (Self::Binary(p),Scalar::Binary(a),Scalar::Binary(b))=>Scalar::Binary(if a.is_in_small_field()&&b.is_in_small_field(){
            let base=Gf2Profile::new(p.w_p,p.w_p).expect("base field");
            let value=Gf2Element::from_bytes(base,*a.as_bytes()).unwrap().mul(&Gf2Element::from_bytes(base,*b.as_bytes()).unwrap());
            Gf2Element::from_bytes(*p,*value.as_bytes()).unwrap()
        }else if b.is_in_small_field(){a.mul_small(b)}else if a.is_in_small_field(){b.mul_small(a)}else{a.mul(b)}), _=>unreachable!(),
    } }
    fn inv(&self,a:&Scalar)->Option<Scalar> { if is_zero(a) { return None; } Some(match (self,a) {
        (Self::Prime(p),Scalar::Prime(a))=>Scalar::Prime(a.modpow(&(p-BigUint::from(2u8)),p)),
        (Self::Binary(p),Scalar::Binary(a))=>Scalar::Binary(if a.is_in_small_field(){
            let base=Gf2Profile::new(p.w_p,p.w_p).expect("base field");let inverse=Gf2Element::from_bytes(base,*a.as_bytes()).unwrap().inv();
            Gf2Element::from_bytes(*p,*inverse.as_bytes()).unwrap()
        }else{a.inv()}), _=>unreachable!(),
    }) }
    fn id(&self)->Vec<u8> { match self { Self::Prime(p)=>{let mut b=vec![0];b.extend(p.to_bytes_be());b},Self::Binary(p)=>vec![1,(p.w_p/8) as u8,(p.w_q/8) as u8] } }
    pub(crate) fn canonical(&self,bytes:&[u8])->bool { self.parse(bytes).is_some() }
}
fn is_zero(a:&Scalar)->bool { match a { Scalar::Prime(a)=>a.is_zero(),Scalar::Binary(a)=>a.is_zero() } }
fn equal(a:&Scalar,b:&Scalar)->bool { match (a,b) { (Scalar::Prime(a),Scalar::Prime(b))=>a==b,(Scalar::Binary(a),Scalar::Binary(b))=>a.as_bytes()==b.as_bytes(),_=>false } }
fn evaluate(field:&Field,coeffs:&[Scalar],x:&Scalar)->Scalar { coeffs.iter().rev().fold(field.zero(),|v,c|field.add(&field.mul(&v,x),c)) }

#[derive(Clone, Debug)]
pub(crate) struct Polynomial { field:Field, coefficients:Vec<Scalar>, pub support:Vec<Replica>, pub errors:Vec<Replica> }
impl Polynomial {
    pub(crate) fn at_point(&self,provider:Replica)->Vec<u8> { self.field.bytes(&evaluate(&self.field,&self.coefficients,&self.field.point(provider))) }
    pub(crate) fn at_zero(&self)->Vec<u8> { self.field.bytes(&self.coefficients[0]) }
}

#[derive(Default, Debug)]
pub(crate) struct OecCache { inverses:HashMap<(Vec<u8>,Vec<Replica>),Vec<Vec<Scalar>>> }

/// Gauss-Jordan on a possibly overdetermined augmented system. Free variables
/// are set to zero; inconsistent rows are rejected, never silently discarded.
fn solve(field:&Field,mut rows:Vec<Vec<Scalar>>,unknowns:usize)->Option<Vec<Scalar>> {
    let mut pivot=0; let mut columns=Vec::new();
    for col in 0..unknowns {
        let found=(pivot..rows.len()).find(|r|!is_zero(&rows[*r][col]));
        let found=match found {Some(v)=>v,None=>continue}; rows.swap(pivot,found);
        let inv=field.inv(&rows[pivot][col])?;
        for j in col..=unknowns { rows[pivot][j]=field.mul(&rows[pivot][j],&inv); }
        let base=rows[pivot].clone();
        for r in 0..rows.len() { if r==pivot {continue;} let factor=rows[r][col].clone(); if is_zero(&factor) {continue;}
            for j in col..=unknowns { rows[r][j]=field.sub(&rows[r][j],&field.mul(&factor,&base[j])); }
        }
        columns.push(col); pivot+=1; if pivot==rows.len(){break;}
    }
    if rows.iter().any(|row|row[..unknowns].iter().all(is_zero)&&!is_zero(&row[unknowns])) {return None;}
    let mut result=vec![field.zero();unknowns];
    for (r,col) in columns.into_iter().enumerate(){result[col]=rows[r][unknowns].clone();}
    Some(result)
}

fn interpolate(field:&Field,points:&[(Replica,Scalar)],cache:&mut OecCache)->Option<Vec<Scalar>> {
    let providers:Vec<_>=points.iter().map(|(p,_)|*p).collect(); let key=(field.id(),providers); let k=points.len();
    if !cache.inverses.contains_key(&key) {
        let mut inverse=vec![vec![field.zero();k];k];
        for column in 0..k {
            let rows=points.iter().enumerate().map(|(r,(provider,_))|{
                let x=field.point(*provider); let mut power=field.one(); let mut row=Vec::with_capacity(k+1);
                for _ in 0..k { row.push(power.clone());power=field.mul(&power,&x); }
                row.push(if r==column {field.one()}else{field.zero()}); row
            }).collect();
            let solution=solve(field,rows,k)?;
            for r in 0..k {inverse[r][column]=solution[r].clone();}
        }
        cache.inverses.insert(key.clone(),inverse);
    }
    let inverse=&cache.inverses[&key];
    Some(inverse.iter().map(|row|row.iter().zip(points).fold(field.zero(),|sum,(weight,(_,y))|field.add(&sum,&field.mul(weight,y)))).collect())
}

fn confirm(field:&Field,coefficients:Vec<Scalar>,points:&[(Replica,Scalar)],degree:usize,faults:usize)->Option<Polynomial> {
    if coefficients.len()>degree+1 {return None;}
    let mut support=Vec::new();let mut errors=Vec::new();
    for (provider,y) in points {if equal(&evaluate(field,&coefficients,&field.point(*provider)),y){support.push(*provider);}else{errors.push(*provider);}}
    if support.len()<degree+faults+1 || errors.len()>faults {return None;}
    Some(Polynomial {field:field.clone(),coefficients,support,errors})
}

pub(crate) fn decode(field:&Field,degree:usize,faults:usize,n:usize,
    input:&BTreeMap<Replica,Vec<u8>>,cache:&mut OecCache)->Option<Polynomial> {
    let points:Vec<_>=input.iter().filter(|(p,_)|**p<n).filter_map(|(p,b)|field.parse(b).map(|v|(*p,v))).collect();
    let k=degree+1;if points.len()<k+faults{return None;}
    if let Some(coefficients)=interpolate(field,&points[..k],cache){if let Some(p)=confirm(field,coefficients,&points,degree,faults){return Some(p);}}
    for errors in 1..=faults.min((points.len()-k)/2) {
        let q_len=k+errors;let unknowns=q_len+errors;
        let rows=points.iter().map(|(provider,y)|{
            let x=field.point(*provider);let mut powers=vec![field.one()];
            for i in 1..q_len {powers.push(field.mul(&powers[i-1],&x));}
            let mut row=powers.clone();
            for power in powers.iter().take(errors){row.push(field.sub(&field.zero(),&field.mul(y,power)));}
            row.push(field.mul(y,&powers[errors]));row
        }).collect();
        let solution=match solve(field,rows,unknowns){Some(s)=>s,None=>continue};
        let mut remainder=solution[..q_len].to_vec(); let mut locator=solution[q_len..].to_vec();locator.push(field.one());
        let mut coefficients=vec![field.zero();k];
        for i in (errors..q_len).rev(){let c=remainder[i].clone();let offset=i-errors;coefficients[offset]=c.clone();
            for j in 0..=errors {remainder[offset+j]=field.sub(&remainder[offset+j],&field.mul(&c,&locator[j]));}
        }
        if remainder.iter().any(|v|!is_zero(v)){continue;}
        if let Some(p)=confirm(field,coefficients,&points,degree,faults){return Some(p);}
    }
    None
}

pub(crate) fn val(bytes:&[u8])->Option<types::beacon::Val> {if bytes.len()>32{return None;}let mut value=[0u8;32];value[32-bytes.len()..].copy_from_slice(bytes);Some(value)}
