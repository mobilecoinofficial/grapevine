// Copyright (c) 2018-2023 The MobileCoin Foundation

//! A marshalled record

use super::{MessageBusValueSize, MsgId};
use aligned_cmov::{
    typenum::{Diff, U32, U64, U72, U8},
    A8Bytes, AsNeSlice,
};
use generic_array::sequence::Split;
use mc_bomb_enclave_api::QueryError;
use mc_bomb_types::Record;

/// A record marshalled to the layout of a value in the oblivious message bus.
///
/// The layout is:
/// 0..32 = sender bytes
/// 32..64 = recipient bytes
/// 64..72 = timestamp bytes (native endian)
/// 72...  = payload bytes
///
/// The total size is determined by the MessageBusValueSize constant, which is
/// determined by the choice of ORAM parameters, and the size of the message bus
/// key.
///
/// The payload, and record, are always fixed size given these parameters.
#[derive(Default)]
pub struct MarshalledRecord {
    data: A8Bytes<MessageBusValueSize>,
}

impl AsRef<A8Bytes<MessageBusValueSize>> for MarshalledRecord {
    fn as_ref(&self) -> &A8Bytes<MessageBusValueSize> {
        &self.data
    }
}

impl AsMut<A8Bytes<MessageBusValueSize>> for MarshalledRecord {
    fn as_mut(&mut self) -> &mut A8Bytes<MessageBusValueSize> {
        &mut self.data
    }
}

impl From<A8Bytes<MessageBusValueSize>> for MarshalledRecord {
    fn from(data: A8Bytes<MessageBusValueSize>) -> Self {
        Self { data }
    }
}

impl MarshalledRecord {
    /// Take proto record, and extract a properly marshalled key-value pair for
    /// the message bus, consisting of a MsgId and an aligned buffer which is
    /// the value.
    pub fn new_from_proto(proto_record: &Record) -> Result<(MsgId, Self), QueryError> {
        let mut msg_id = MsgId::default();
        if proto_record.msg_id.len() != msg_id.as_slice().len() {
            return Err(QueryError::InvalidMessageIdLength(
                proto_record.msg_id.len(),
                msg_id.as_slice().len(),
            ));
        }
        msg_id
            .as_mut_slice()
            .copy_from_slice(&proto_record.msg_id[..]);

        let mut data: A8Bytes<MessageBusValueSize> = Default::default();
        let (sender, rest): (&mut A8Bytes<U32>, &mut _) = (&mut data).split();
        let (recipient, rest): (&mut A8Bytes<U32>, &mut _) = rest.split();
        let (timestamp, rest): (&mut A8Bytes<U8>, &mut _) = rest.split();

        if proto_record.sender.len() != sender.as_slice().len() {
            return Err(QueryError::InvalidSenderLength(
                proto_record.sender.len(),
                sender.as_slice().len(),
            ));
        }
        sender
            .as_mut_slice()
            .copy_from_slice(&proto_record.sender[..]);

        if proto_record.recipient.len() != recipient.as_slice().len() {
            return Err(QueryError::InvalidRecipientLength(
                proto_record.recipient.len(),
                recipient.as_slice().len(),
            ));
        }
        recipient
            .as_mut_slice()
            .copy_from_slice(&proto_record.recipient[..]);

        timestamp
            .as_mut_slice()
            .copy_from_slice(&proto_record.timestamp.to_ne_bytes());

        if proto_record.payload.len() != rest.as_slice().len() {
            return Err(QueryError::InvalidPayloadLength(
                proto_record.payload.len(),
                rest.as_slice().len(),
            ));
        }
        rest.as_mut_slice()
            .copy_from_slice(&proto_record.payload[..]);

        Ok((msg_id, Self { data }))
    }

    /// Take a marshalled record, and the associated message bus key, and form a
    /// protobuf Record object, unmarshalling the data.
    pub fn to_proto(&self, msg_id: &MsgId) -> Record {
        // 72 = 32 + 32 + 8
        let (_, payload): (&A8Bytes<U72>, _) = (&self.data).split();

        Record {
            msg_id: msg_id.as_slice().to_vec(),
            sender: self.get_sender().as_slice().to_vec(),
            recipient: self.get_recipient().as_slice().to_vec(),
            timestamp: *self.get_timestamp(),
            payload: payload.as_slice().to_vec(),
        }
    }

    /// Extract the bytes which correspond to the sender.
    pub fn get_sender(&self) -> &A8Bytes<U32> {
        let (sender, _): (&A8Bytes<U32>, _) = (&self.data).split();
        sender
    }

    /// Extract the bytes which correspond to the recipient.
    pub fn get_recipient(&self) -> &A8Bytes<U32> {
        let (_sender, rest): (&A8Bytes<U32>, _) = (&self.data).split();
        let (recipient, _rest): (&A8Bytes<U32>, _) = rest.split();
        recipient
    }

    /// Extract a reference to the timestamp, as a u64
    pub fn get_timestamp(&self) -> &u64 {
        let (_sender, mid): (&A8Bytes<U64>, _) = (&self.data).split();
        let (timestamp, _rest): (&A8Bytes<U8>, _) = mid.split();
        &timestamp.as_ne_u64_slice()[0]
    }

    /// Extract a mutable reference to the timestamp, as a u64
    pub fn get_timestamp_mut(&mut self) -> &mut u64 {
        let (_sender, mid): (&mut A8Bytes<U64>, _) = (&mut self.data).split();
        let (timestamp, _rest): (&mut A8Bytes<U8>, _) = mid.split();
        &mut timestamp.as_mut_ne_u64_slice()[0]
    }

    /// Extract a reference to the payload
    pub fn get_payload(&self) -> &A8Bytes<Diff<MessageBusValueSize, U72>> {
        let (_header, payload): (&A8Bytes<U72>, _) = (&self.data).split();
        payload
    }

    /// Extract a mutable reference to the payload
    pub fn get_payload_mut(&mut self) -> &mut A8Bytes<Diff<MessageBusValueSize, U72>> {
        let (_header, payload): (&mut A8Bytes<U72>, _) = (&mut self.data).split();
        payload
    }
}
