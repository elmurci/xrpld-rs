//! XRP Ledger protocol messages in [protobuf](https://developers.google.com/protocol-buffers).

#![feature(cell_leak)]

pub mod xrpl;

use std::{cell::{Ref, RefCell}, net::SocketAddr};
use crate::tm_ping::PingType;
use bytes::{Buf, BufMut};
use prost::Message as _;
pub use prost::{DecodeError, EncodeError};
use tm_endpoints::TmEndpointv2;
use xrpl::*;

/// Encode/Decode trait.
pub trait EncodeDecode {
    /// Encode/decode trait for type.
    type Type;

    /// Returns the encoded length of the message.
    fn encoded_len(&self) -> usize;

    /// Encode the message to a buffer.
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError>;

    /// Decode an intsance of the message from a buffer.
    fn decode<B: Buf>(buf: &mut B) -> Result<Self::Type, DecodeError>;
}

// Implement EncodeDecode trait for struct.
macro_rules! impl_encode_decode {
    ($type:ty, $inner:ty) => {
        impl EncodeDecode for $type {
            type Type = $type;

            fn encoded_len(&self) -> usize {
                self.to_inner().encoded_len()
            }

            fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
                self.to_inner().encode(buf)
            }

            fn decode<B: Buf>(buf: &mut B) -> Result<Self::Type, DecodeError> {
                let inner = <$inner>::decode(buf)?;
                Ok(Self::Type::from_inner(inner))
            }
        }
    };
}

// Default functions for manipulating with inner.
macro_rules! impl_inner_fns {
    ($type:ty, $inner:ty) => {
        impl $type {
            fn from_inner(inner: $inner) -> Self {
                Self { inner }
            }

            fn to_inner(&self) -> &$inner {
                &self.inner
            }
        }
    };
}

/// All possible messages in protocol
#[derive(Debug)]
pub enum Message {
    Manifests(TmManifests),
    PingPong(PingPong),
    Cluster(TmCluster),
    Endpoints(Endpoints),
    Transaction(TmTransaction),
    GetLedger(TmGetLedger),
    LedgerData(TmLedgerData),
    ProposeLedger(TmProposeSet),
    StatusChange(TmStatusChange),
    HaveSet(TmHaveTransactionSet),
    Validation(TmValidation),
    GetObject(TmGetObjectByHash),
    Validatorlist(TmValidatorList),
    Validatorlistcollection(TmValidatorListCollection),
    ProofPathReq(TmProofPathRequest),
    ProofPathResponse(TmProofPathResponse),
    ReplayDeltaReq(TmReplayDeltaRequest),
    ReplayDeltaResponse(TmReplayDeltaResponse),
    Transactions(TmTransactions),
    HaveTransactions(TmHaveTransactions),
    Squelch(TmSquelch),
}

impl Message {
    /// Check that message type is valid.
    pub fn is_valid_type<B: Buf>(buf: &B) -> bool {
        let bytes = buf.chunk();
        let ty = ((bytes[0] as u16) << 8) + (bytes[1] as u16);
        MessageType::is_valid(ty as i32)
    }
}

impl EncodeDecode for Message {
    type Type = Message;

    /// Returns the encoded length of the message.
    fn encoded_len(&self) -> usize {
        2 + match *self {
            Self::Manifests(ref v) => v.encoded_len(),
            Self::PingPong(ref v) => v.encoded_len(),
            Self::Cluster(ref v) => v.encoded_len(),
            Self::Endpoints(ref v) => v.encoded_len(),
            Self::Transaction(ref v) => v.encoded_len(),
            Self::GetLedger(ref v) => v.encoded_len(),
            Self::LedgerData(ref v) => v.encoded_len(),
            Self::ProposeLedger(ref v) => v.encoded_len(),
            Self::StatusChange(ref v) => v.encoded_len(),
            Self::HaveSet(ref v) => v.encoded_len(),
            Self::Validation(ref v) => v.encoded_len(),
            Self::GetObject(ref v) => v.encoded_len(),
            Self::Validatorlist(ref v) => v.encoded_len(),
            Self::Validatorlistcollection(ref v) => v.encoded_len(),
            Self::ProofPathReq(ref v) => v.encoded_len(),
            Self::ProofPathResponse(ref v) => v.encoded_len(),
            Self::ReplayDeltaReq(ref v) => v.encoded_len(),
            Self::ReplayDeltaResponse(ref v) => v.encoded_len(),
            Self::Transactions(ref v) => v.encoded_len(),
            Self::HaveTransactions(ref v) => v.encoded_len(),
            Self::Squelch(ref v) => v.encoded_len(),
        }
    }

    /// Encode the message to a buffer.
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        use MessageType::*;

        let message_type = match *self {
            Self::Manifests(_) => MtManifests,
            Self::PingPong(_) => MtPing,
            Self::Cluster(_) => MtCluster,
            Self::Endpoints(_) => MtEndpoints,
            Self::Transaction(_) => MtTransaction,
            Self::GetLedger(_) => MtGetLedger,
            Self::LedgerData(_) => MtLedgerData,
            Self::ProposeLedger(_) => MtProposeLedger,
            Self::StatusChange(_) => MtStatusChange,
            Self::HaveSet(_) => MtHaveSet,
            Self::Validation(_) => MtValidation,
            Self::GetObject(_) => MtGetObjects,
            Self::Validatorlist(_) => MtValidatorlist,
            Self::Validatorlistcollection(_) => MtValidatorlistcollection,
            Self::ProofPathReq(_) => MtProofPathReq,
            Self::ProofPathResponse(_) => MtProofPathResponse,
            Self::ReplayDeltaReq(_) => MtReplayDeltaReq,
            Self::ReplayDeltaResponse(_) => MtReplayDeltaResponse,
            Self::Transactions(_) => MtTransactions,
            Self::HaveTransactions(_) => MtHaveTransactions,
            Self::Squelch(_) => MtSquelch,

        };
        buf.put_u16(message_type as u16);

        match *self {
            Self::Manifests(ref v) => v.encode(buf),
            Self::PingPong(ref v) => v.encode(buf),
            Self::Cluster(ref v) => v.encode(buf),
            Self::Endpoints(ref v) => v.encode(buf),
            Self::Transaction(ref v) => v.encode(buf),
            Self::GetLedger(ref v) => v.encode(buf),
            Self::LedgerData(ref v) => v.encode(buf),
            Self::ProposeLedger(ref v) => v.encode(buf),
            Self::StatusChange(ref v) => v.encode(buf),
            Self::HaveSet(ref v) => v.encode(buf),
            Self::Validation(ref v) => v.encode(buf),
            Self::GetObject(ref v) => v.encode(buf),
            Self::Validatorlist(ref v) => v.encode(buf),
            Self::Validatorlistcollection(ref v) => v.encode(buf),
            Self::ProofPathReq(ref v) => v.encode(buf),
            Self::ProofPathResponse(ref v) => v.encode(buf),
            Self::ReplayDeltaReq(ref v) => v.encode(buf),
            Self::ReplayDeltaResponse(ref v) => v.encode(buf),
            Self::Transactions(ref v) => v.encode(buf),
            Self::HaveTransactions(ref v) => v.encode(buf),
            Self::Squelch(ref v) => v.encode(buf),


        }
    }

    /// Decode an intsance of the message from a buffer.
    fn decode<B: Buf>(buf: &mut B) -> Result<Self::Type, DecodeError> {
        use MessageType::*;

        let message_type = buf.get_u16() as i32;
        let message_type = MessageType::from_i32(message_type)
            .ok_or_else(|| DecodeError::new("invalid message"))?;

        Ok(match message_type {
            MtManifests => Message::Manifests(TmManifests::decode(buf)?),
            MtPing => Message::PingPong(PingPong::decode(buf)?),
            MtCluster => Message::Cluster(TmCluster::decode(buf)?),
            MtEndpoints => Message::Endpoints(Endpoints::decode(buf)?),
            MtTransaction => Message::Transaction(TmTransaction::decode(buf)?),
            MtGetLedger => Message::GetLedger(TmGetLedger::decode(buf)?),
            MtLedgerData => Message::LedgerData(TmLedgerData::decode(buf)?),
            MtProposeLedger => Message::ProposeLedger(TmProposeSet::decode(buf)?),
            MtStatusChange => Message::StatusChange(TmStatusChange::decode(buf)?),
            MtHaveSet => Message::HaveSet(TmHaveTransactionSet::decode(buf)?),
            MtValidation => Message::Validation(TmValidation::decode(buf)?),
            MtValidatorlist => Message::Validatorlist(TmValidatorList::decode(buf)?),
            MtSquelch => Message::Squelch(TmSquelch::decode(buf)?),
            MtValidatorlistcollection => Message::Validatorlistcollection(TmValidatorListCollection::decode(buf)?),
            MtProofPathReq => Message::ProofPathReq(TmProofPathRequest::decode(buf)?),
            MtProofPathResponse => Message::ProofPathResponse(TmProofPathResponse::decode(buf)?),
            MtReplayDeltaReq => Message::ReplayDeltaReq(TmReplayDeltaRequest::decode(buf)?),
            MtReplayDeltaResponse => Message::ReplayDeltaResponse(TmReplayDeltaResponse::decode(buf)?),
            MtHaveTransactions => Message::HaveTransactions(TmHaveTransactions::decode(buf)?),
            MtTransactions => Message::Transactions(TmTransactions::decode(buf)?),
            MtGetObjectByHash => Message::GetObject(TmGetObjectByHash::decode(buf)?),
        })
    }
}

/// Ping/Pong message. This messages used for checking that connected peer is alive.
#[derive(Debug)]
pub struct PingPong {
    inner: TmPing,
}

impl_encode_decode!(PingPong, TmPing);
impl_inner_fns!(PingPong, TmPing);

impl PingPong {
    fn build(r#type: PingType, seq: Option<u32>) -> Self {
        let r#type = r#type as i32;
        Self::from_inner(TmPing {
            r#type,
            seq,
            ping_time: None,
            net_time: None,
        })
    }

    /// Build ping type.
    pub fn build_ping(seq: Option<u32>) -> Self {
        Self::build(PingType::PtPing, seq)
    }

    /// Build pong type.
    pub fn build_pong(seq: Option<u32>) -> Self {
        Self::build(PingType::PtPong, seq)
    }

    /// Return true if ping message.
    pub fn is_ping(&self) -> bool {
        self.inner.r#type() == PingType::PtPing
    }

    /// Return message sequence.
    pub fn sequence(&self) -> Option<u32> {
        self.inner.seq
    }
}

/// Represent exactly one endpoint.
#[allow(missing_docs)]
#[derive(Debug)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub hops: u32,
}

/// Endpoints message. TODO: more
#[derive(Debug)]
pub struct Endpoints {
    inner: RefCell<TmEndpoints>,
    /// Vec of [`Endpoint`][Endpoint].
    pub endpoints: Vec<Endpoint>,
}

impl_encode_decode!(Endpoints, TmEndpoints);

impl Default for Endpoints {
    fn default() -> Self {
        Self::from_inner(TmEndpoints {
            version: 2,
            endpoints_v2: vec![],
        })
    }
}

impl Endpoints {
    fn from_inner(inner: TmEndpoints) -> Self {
        // We ignore `endpoints`, because they outdated.
        // `endpoints_v2` have both IPv4 & IPv6.
        let endpoints = inner
            .endpoints_v2
            .iter()
            .filter_map(|s| {
                s.endpoint
                    .parse::<SocketAddr>()
                    .map(|addr| Endpoint { addr, hops: s.hops })
                    .ok()
            })
            .collect();

        Self {
            inner: RefCell::new(inner),
            endpoints,
        }
    }

    fn to_inner(&self) -> &TmEndpoints {
        self.inner.borrow_mut().endpoints_v2 = self
            .endpoints
            .iter()
            .map(|s| TmEndpointv2 {
                endpoint: s.addr.to_string(),
                hops: s.hops,
            })
            .collect();

        Ref::leak(self.inner.borrow())
    }
}