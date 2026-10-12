//! Deployment assumptions are explicit and do not alter microbenchmark defaults.
use anyhow::{anyhow, Result};
use crypto::gf2::Gf2Profile;
use config::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PptChannel { Benchmark, Private, ExternalPrivate }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PptOptions {
    pub channel: PptChannel,
    pub target128: bool,
}

impl Default for PptOptions {
    fn default() -> Self { Self { channel: PptChannel::Benchmark, target128: false } }
}

impl PptOptions {
    pub fn parse(channel: &str, security: &str) -> Result<Self> {
        let channel = match channel {
            "benchmark" => PptChannel::Benchmark,
            "private" => PptChannel::Private,
            "external-private" => PptChannel::ExternalPrivate,
            _ => return Err(anyhow!("--ppt-channel must be benchmark, private or external-private")),
        };
        let target128 = match security {
            "benchmark" => false,
            "target128" => true,
            _ => return Err(anyhow!("--ppt-security must be benchmark or target128")),
        };
        Ok(Self { channel, target128 })
    }

    pub(crate) fn validate(self, config: &Node, profile: Option<Gf2Profile>, transport: super::context::AvssTransport) -> Result<()> {
        if self.channel == PptChannel::Private {
            for peer in 0..config.num_nodes {
                if peer != config.id && config.sk_map.get(&peer).map(|key| key.len()) != Some(32) {
                    return Err(anyhow!("PPT private channel needs a provisioned 32-byte secret for every peer"));
                }
            }
        }
        if self.target128 {
            if transport != super::context::AvssTransport::SecMsg {
                return Err(anyhow!("target128 requires SecMsg's transferable recovery evidence; Lite remains an explicit private-channel comparison"));
            }
            if self.channel == PptChannel::Benchmark {
                return Err(anyhow!("target128 requires private or an explicitly asserted external-private channel"));
            }
            let profile = profile.ok_or_else(|| anyhow!("target128 requires a true GF2 extension; legacy prime fields are a comparison mode"))?;
            let minimum = 128usize.checked_add(config.num_nodes)
                .ok_or_else(|| anyhow!("PPT large-field bound overflow"))?;
            if profile.w_q <= minimum {
                return Err(anyhow!("PPT target128 needs w_q > 128+n, got w_q={} n={}", profile.w_q, config.num_nodes));
            }
        }
        Ok(())
    }
}
