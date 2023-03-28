// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Helpers for handling marshalled records in the ORAM

use super::{MessageBusValueSize, MsgId};
use aligned_cmov::{
    typenum::{Diff, U32, U64, U72, U8},
    A8Bytes, AsNeSlice,
};
use generic_array::sequence::Split;
use mc_grapevine_enclave_api::QueryError;
use mc_grapevine_types::{Record, RequestRecord};

/// This trait adds a bunch of helper functions for manipulating records
/// marshalled to the layout of a value in the oblivious message bus.
///
/// The only intended implementer is A8Bytes<MessageBusValueSize>.
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
pub trait MarshalledRecord: Sized {
    /// Create a MarshalledRecord from a RequestRecord proto object
    ///
    /// Returns:
    /// * A MsgId object, and Self
    /// * Errors if any of the fields in the protobuf are the wrong size
    fn new_from_proto(proto_record: &RequestRecord) -> Result<(MsgId, Self), QueryError>;

    /// Take a MarshalledRecord, and the associated message bus key, and form a
    /// protobuf Record object, unmarshalling the data and formatting it for
    /// return to the user.
    fn to_proto(&self, msg_id: &MsgId) -> Record;

    /// Get a reference to the bytes which correspond to the sender.
    fn get_sender(&self) -> &A8Bytes<U32>;

    /// Get a mutable reference to the bytes which correspond to the sender.
    fn get_sender_mut(&mut self) -> &mut A8Bytes<U32>;

    /// Get a reference to the bytes which correspond to the recipient.
    fn get_recipient(&self) -> &A8Bytes<U32>;

    /// Get a mutable reference to the bytes which correspond to the recipient.
    fn get_recipient_mut(&mut self) -> &mut A8Bytes<U32>;

    /// Get a reference to the timestamp, as a u64
    fn get_timestamp(&self) -> &u64;

    /// Get a mutable reference to the timestamp, as a u64
    fn get_timestamp_mut(&mut self) -> &mut u64;

    /// Get a reference to the payload bytes
    fn get_payload(&self) -> &A8Bytes<Diff<MessageBusValueSize, U72>>;

    /// Get a mutable reference to the payload bytes
    fn get_payload_mut(&mut self) -> &mut A8Bytes<Diff<MessageBusValueSize, U72>>;
}

impl MarshalledRecord for A8Bytes<MessageBusValueSize> {
    fn new_from_proto(proto_record: &RequestRecord) -> Result<(MsgId, Self), QueryError> {
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
        let (_sender, rest): (&mut A8Bytes<U32>, &mut _) = (&mut data).split();
        let (recipient, rest): (&mut A8Bytes<U32>, &mut _) = rest.split();
        let (_timestamp, rest): (&mut A8Bytes<U8>, &mut _) = rest.split();

        if proto_record.recipient.len() != recipient.as_slice().len() {
            return Err(QueryError::InvalidRecipientLength(
                proto_record.recipient.len(),
                recipient.as_slice().len(),
            ));
        }
        recipient
            .as_mut_slice()
            .copy_from_slice(&proto_record.recipient[..]);

        if proto_record.payload.len() != rest.as_slice().len() {
            return Err(QueryError::InvalidPayloadLength(
                proto_record.payload.len(),
                rest.as_slice().len(),
            ));
        }
        rest.as_mut_slice()
            .copy_from_slice(&proto_record.payload[..]);

        Ok((msg_id, data))
    }

    fn to_proto(&self, msg_id: &MsgId) -> Record {
        Record {
            msg_id: msg_id.as_slice().to_vec(),
            sender: self.get_sender().as_slice().to_vec(),
            recipient: self.get_recipient().as_slice().to_vec(),
            timestamp: *self.get_timestamp(),
            payload: self.get_payload().as_slice().to_vec(),
        }
    }

    fn get_sender(&self) -> &A8Bytes<U32> {
        let (sender, _): (&A8Bytes<U32>, _) = self.split();
        sender
    }

    fn get_sender_mut(&mut self) -> &mut A8Bytes<U32> {
        let (sender, _): (&mut A8Bytes<U32>, _) = self.split();
        sender
    }

    fn get_recipient(&self) -> &A8Bytes<U32> {
        let (_sender, rest): (&A8Bytes<U32>, _) = self.split();
        let (recipient, _rest): (&A8Bytes<U32>, _) = rest.split();
        recipient
    }

    fn get_recipient_mut(&mut self) -> &mut A8Bytes<U32> {
        let (_sender, rest): (&mut A8Bytes<U32>, _) = self.split();
        let (recipient, _rest): (&mut A8Bytes<U32>, _) = rest.split();
        recipient
    }

    fn get_timestamp(&self) -> &u64 {
        let (_sender, mid): (&A8Bytes<U64>, _) = self.split();
        let (timestamp, _rest): (&A8Bytes<U8>, _) = mid.split();
        &timestamp.as_ne_u64_slice()[0]
    }

    fn get_timestamp_mut(&mut self) -> &mut u64 {
        let (_sender, mid): (&mut A8Bytes<U64>, _) = self.split();
        let (timestamp, _rest): (&mut A8Bytes<U8>, _) = mid.split();
        &mut timestamp.as_mut_ne_u64_slice()[0]
    }

    fn get_payload(&self) -> &A8Bytes<Diff<MessageBusValueSize, U72>> {
        let (_header, payload): (&A8Bytes<U72>, _) = self.split();
        payload
    }

    fn get_payload_mut(&mut self) -> &mut A8Bytes<Diff<MessageBusValueSize, U72>> {
        let (_header, payload): (&mut A8Bytes<U72>, _) = self.split();
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_util_from_random::FromRandom;
    use mc_util_test_helper::run_with_several_seeds;
    use zeroize::Zeroize;

    #[test]
    fn test_accessors() {
        run_with_several_seeds(|mut rng| {
            let req_rec = RequestRecord::from_random(&mut rng);

            let (id, mut marshalled_record) =
                <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec)
                    .unwrap();

            assert_eq!(&id[..], &req_rec.msg_id[..]);
            assert_eq!(
                marshalled_record.get_recipient().as_slice(),
                &req_rec.recipient[..]
            );
            assert_eq!(
                marshalled_record.get_payload().as_slice(),
                &req_rec.payload[..]
            );

            *marshalled_record.get_timestamp_mut() = 54;
            assert_eq!(*marshalled_record.get_timestamp(), 54);

            marshalled_record
                .get_sender_mut()
                .as_mut_slice()
                .copy_from_slice(&[7u8; 32]);
            assert_eq!(marshalled_record.get_sender().as_slice(), &[7u8; 32]);

            marshalled_record
                .get_recipient_mut()
                .as_mut_slice()
                .copy_from_slice(&[9u8; 32]);
            assert_eq!(marshalled_record.get_recipient().as_slice(), &[9u8; 32]);

            marshalled_record.get_payload_mut().zeroize();
            assert_eq!(marshalled_record.get_payload(), &Default::default());
        })
    }

    #[test]
    fn test_bounds_checks() {
        run_with_several_seeds(|mut rng| {
            let mut req_rec = RequestRecord::from_random(&mut rng);
            <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec).unwrap();

            req_rec.msg_id.resize(17, 0u8);
            assert!(
                <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec)
                    .is_err()
            );

            req_rec.msg_id.resize(15, 0u8);
            assert!(
                <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec)
                    .is_err()
            );

            req_rec.msg_id.resize(16, 0u8);
            <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec).unwrap();

            req_rec.recipient.resize(33, 0u8);
            assert!(
                <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec)
                    .is_err()
            );

            req_rec.recipient.resize(31, 0u8);
            assert!(
                <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec)
                    .is_err()
            );

            req_rec.recipient.resize(32, 0u8);
            <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec).unwrap();

            req_rec.payload.resize(937, 0u8);
            assert!(
                <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec)
                    .is_err()
            );

            req_rec.payload.resize(935, 0u8);
            assert!(
                <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec)
                    .is_err()
            );

            req_rec.payload.resize(936, 0u8);
            <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec).unwrap();
        })
    }

    #[test]
    fn test_round_tripping() {
        run_with_several_seeds(|mut rng| {
            let req_rec = RequestRecord::from_random(&mut rng);

            let (id, marshalled_record) =
                <A8Bytes<MessageBusValueSize> as MarshalledRecord>::new_from_proto(&req_rec)
                    .unwrap();

            let rec = marshalled_record.to_proto(&id);

            assert_eq!(rec.msg_id, req_rec.msg_id);
            assert_eq!(rec.recipient, req_rec.recipient);
            assert_eq!(rec.payload, req_rec.payload);

            assert_eq!(marshalled_record.get_sender().as_slice(), &rec.sender[..]);
            assert_eq!(*marshalled_record.get_timestamp(), rec.timestamp);
        })
    }
}
