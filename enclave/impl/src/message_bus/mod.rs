// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Object representing trusted storage for message bus contents.
//! This stores messages by ids, and associates a fixed size storage to each
//! recipient containing a list of in-flight ids.
//! The message bus object ensures that these are in sync and that expired
//! messages are purged lazily over time.

use aligned_cmov::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess},
    typenum::{U1008, U1024, U16, U24, U32, U4096, U64, U8, U992},
    A8Bytes, Aligned, AsAlignedChunks, AsNeSlice, CMov,
};
use alloc::boxed::Box;
use generic_array::sequence::Split;
use mc_bomb_enclave_api::QueryError;
use mc_bomb_types::{
    QueryRequest, QueryResponse, STATUS_CODE_INTERNAL_ERROR, STATUS_CODE_INVALID_RECIPIENT,
    STATUS_CODE_SUCCESS,
};
use mc_crypto_keys::{RistrettoPublic, RistrettoSignature};
use mc_crypto_rand::McRng;
use mc_oblivious_map::CuckooHashTableCreator;
use mc_oblivious_ram::PathORAM4096Z4Creator;
use mc_oblivious_traits::{
    OMapCreator, ORAMStorageCreator, ObliviousHashMap, /* OMAP_FOUND, */ OMAP_INVALID_KEY,
    OMAP_NOT_FOUND, OMAP_OVERFLOW,
};

mod marshalled_record;
use marshalled_record::MarshalledRecord;

// internal constants

// KeySize and ValueSize reflect the needs of message bus
// We must choose an oblivious map algorithm that can support that
// The message bus key is one 16 byte id
// The message bus value is 1008 remaining bytes. These get mapped into protobuf
// as described in the README, and the user's payload is somewhere in there.
type MessageBusKeySize = U16;
type MessageBusValueSize = U1008; // 1008 = 1024 - 16

// Type alias for the key to the message bus map (a "Message Id")
type MsgId = A8Bytes<MessageBusKeySize>;

// The recipient-to-message-id map maps recipient pubkeys to the ids of their
// messages. A recipient key is 32 bytes.
// The value is 1024 - 32 bytes, divided into 24 byte chunks which are an id and
// a timestamp.
type RecipientKeySize = U32;
type RecipientValueSize = U992; // 992 = 1024 - 32

// BlockSize is a tuning parameter for OMap which must become the ValueSize of
// the selected ORAM
type BlockSize = U1024;

// This selects an oblivious ram algorithm which can support queries of size
// BlockSize The ORAMStorageCreator type is a generic parameter to ETxOutStore
type ObliviousRAMAlgo<OSC> = PathORAM4096Z4Creator<McRng, OSC>;

// These are the requirements on the storage, this is imposed by the choice of
// oram algorithm
pub type StorageDataSize = U4096;
pub type StorageMetaSize = U64;

// This selects the stash size we will construct the oram with
const STASH_SIZE: usize = 32;

// This selects the oblivious map algorithm
type ObliviousMapCreator<OSC> = CuckooHashTableCreator<BlockSize, McRng, ObliviousRAMAlgo<OSC>>;

/// Object which holds:
///
/// * An ids-to-messages table for messages in the message bus
/// * A recipients-to-ids table to help recipients find their messages.
///
/// A single recipient can only have a certain number of messages in flight, or
/// there is back-pressure on the senders.
pub struct MessageBus<OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>> {
    /// Oblivious map which maps ids to messages
    ids_to_messages:
        Box<
            <ObliviousMapCreator<OSC> as OMapCreator<
                MessageBusKeySize,
                MessageBusValueSize,
                McRng,
            >>::Output,
        >,

    /// Oblivious map which maps recipients to ids
    recipients_to_ids:
        Box<
            <ObliviousMapCreator<OSC> as OMapCreator<
                RecipientKeySize,
                RecipientValueSize,
                McRng,
            >>::Output,
        >,

    /// The current timestamp value, as reported to us by the untrusted server.
    /// The only thing we do with this is copy this into timestamp fields of new
    /// records, and eventually, the hashmap will have a criteria which
    /// allows us to consider records as blank if their timestamps are
    /// sufficiently far as the past.
    current_timestamp: u64,

    /// Messages are considered expired if their timestamp is this far in the
    /// past.
    message_time_to_live: u64,
}

impl<OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>> MessageBus<OSC> {
    /// Create a new MessageBus object.
    pub fn new(desired_capacity: u64, current_timestamp: u64, message_time_to_live: u64) -> Self {
        Self {
            ids_to_messages: Box::new(<ObliviousMapCreator<OSC> as OMapCreator<
                MessageBusKeySize,
                MessageBusValueSize,
                McRng,
            >>::create(
                desired_capacity, STASH_SIZE, McRng::default
            )),
            recipients_to_ids: Box::new(<ObliviousMapCreator<OSC> as OMapCreator<
                RecipientKeySize,
                RecipientValueSize,
                McRng,
            >>::create(
                desired_capacity, STASH_SIZE, McRng::default
            )),
            current_timestamp,
            message_time_to_live,
        }
    }

    /// Update the current timestamp. This affects what timestamps are assigned
    /// to any subsequent new records that are added, and can cause existing
    /// records to expire and get purged as the current timestamp increases.
    pub fn set_current_timestamp(&mut self, current_timestamp: u64) {
        self.current_timestamp = current_timestamp;
    }

    /// Update the message time-to-live value. This may cause more or fewer
    /// messages to be purged going forwards.
    pub fn set_message_time_to_live(&mut self, msg_ttl: u64) {
        self.message_time_to_live = msg_ttl;
    }

    /// Handle a query.
    ///
    /// This is not constant time across different CRUD operations, but for any
    /// given CRUD operation it should be. The helper functions document what
    /// they do and what their limitations are.
    pub fn handle_query(
        &mut self,
        query: &QueryRequest,
        challenge_value: &[u8; 32],
    ) -> Result<QueryResponse, QueryError> {
        // First, authenticate the user, checking their signature over the
        // challenge value.
        let decompressed_identity = RistrettoPublic::try_from(&query.auth_identity[..])?;
        let sig = RistrettoSignature::try_from(&query.auth_signature[..])?;
        decompressed_identity.verify_schnorrkel(b"mc-bomb-challenge", challenge_value, &sig)?;

        // In the specific case that the caller did not set request type to a nonzero
        // value, fail hard and fast, because this breaks security.
        // Otherwise, I believe that unknown request types will be interpretted as READ
        if bool::from(query.request_type.ct_eq(&0)) {
            return Err(QueryError::InvalidRequestType.into());
        }

        // Call the appropriate helper
        match query.request_type {
            1 => Ok(self.create_record(query)?),
            _ => Ok(self.access_record(query)?),
        }
    }

    // Handle a create record request.
    fn create_record(&mut self, query: &QueryRequest) -> Result<QueryResponse, QueryError> {
        let mut rng = McRng::default();
        let (id, mut marshalled) = MarshalledRecord::new_from_proto(&query.record)?;

        *marshalled.get_timestamp_mut() = self.current_timestamp;

        let mut insertion_succeeds = Choice::from(0);
        let mut message_omap_result_code = 0u32;
        let recipient_omap_result_code = self.recipients_to_ids.access_and_insert(
            &marshalled.get_recipient(),
            &Default::default(),
            &mut rng,
            |_code, buffer| {
                let mut found_key = Choice::from(0);
                let mut found_key_needs_overwrite = Choice::from(0);
                let mut found_free_space = Choice::from(0);
                let mut desired_index = u64::MAX;

                // Find a place where we can write a new msg id record for this recipient, if
                // possible.
                let chunks: &mut [A8Bytes<U24>] = buffer.as_mut_aligned_chunks();
                for (idx, chunk) in chunks.iter_mut().enumerate() {
                    let (msg_id, timestamp): (&mut A8Bytes<U16>, &mut A8Bytes<U8>) = chunk.split();

                    let msg_id_is_zero = msg_id.ct_eq(&Default::default());
                    let timestamp_expired = (timestamp.as_ne_u64_slice()[0]
                        + self.message_time_to_live)
                        .ct_lt(&self.current_timestamp);
                    let msg_id_is_key = msg_id.ct_eq(&id);

                    // The space is vacant if its id is all zeroes, or the timestamp is expired
                    found_free_space = found_free_space | (msg_id_is_zero | timestamp_expired);
                    found_key = found_key | msg_id_is_key;
                    found_key_needs_overwrite =
                        found_key_needs_overwrite | (msg_id_is_key & timestamp_expired);

                    // If this msg_id matches our key, or it's a free space and we haven't found our
                    // key already, then we should update the desired_index
                    // variable.
                    desired_index.cmov(
                        msg_id_is_key | (!found_key & found_free_space),
                        &(idx as u64),
                    );
                }

                insertion_succeeds = found_key | found_free_space;
                message_omap_result_code = self.ids_to_messages.vartime_write_extended(
                    &id,
                    &marshalled.as_ref(),
                    found_key_needs_overwrite,
                    insertion_succeeds,
                );

                if message_omap_result_code == OMAP_OVERFLOW {
                    // Do something
                    insertion_succeeds = Choice::from(0);
                }

                // Now update the entry in the recipients_to_ids field.
                // We have to do 2 passes here because if we don't, we won't know when we see an
                // empty or expired slot whether to write because we don't know
                // if the same key already appears later in the list.
                let chunks: &mut [A8Bytes<U24>] = buffer.as_mut_aligned_chunks();
                for (idx, chunk) in chunks.iter_mut().enumerate() {
                    let (msg_id, timestamp): (&mut A8Bytes<U16>, &mut A8Bytes<U8>) = chunk.split();

                    let found_desired_idx = (idx as u64).ct_eq(&desired_index);

                    msg_id.cmov(found_desired_idx, &id);
                    timestamp.as_mut_ne_u64_slice()[0]
                        .cmov(found_desired_idx, &self.current_timestamp);
                }
            },
        );

        // If the initial call returned invalid key or overflow, then we failed.
        insertion_succeeds.conditional_assign(
            &(recipient_omap_result_code.ct_eq(&OMAP_INVALID_KEY)
                | recipient_omap_result_code.ct_eq(&OMAP_OVERFLOW)),
            Choice::from(0),
        );

        // write a status code for the request, based on insertion_succeeds and omap
        // result codes
        //
        // If the recipient map overflows:
        // STATUS_CODE_TOO_MANY_USERS
        //
        // If the recipient is invalid:
        // STATUS_CODE_INVALID_RECIPIENT
        //
        // If the recipient's message id table is already full:
        // STATUS_CODE_TOO_MANY_MESSAGES_FOR_USER
        //
        // If the message id is invalid:
        // STATUS_CODE_INVALID_MESSAGE_ID
        //
        // If the message id is already in use:
        // STATUS_CODE_MESSAGE_ID_ALREADY_IN_USE
        //
        // If the message map itself overflows:
        // STATUS_CODE_TOO_MANY_MESSAGES

        // XXX: FIXME
        let mut status_code = STATUS_CODE_INTERNAL_ERROR;
        status_code.cmov(insertion_succeeds, &STATUS_CODE_SUCCESS);

        Ok(QueryResponse {
            record: marshalled.to_proto(&id),
            status_code,
        })
    }

    // There are three types of queries that are handled by this API:
    // Read, Update, and Delete.
    //
    // This call is supposed to be oblivious across all of them.
    //
    // * A read operation returns the message with the specified message id,
    //   provided that the user authenticates as the sender or recipient of that
    //   message.
    // * An update operation modifies the message with the specified message id,
    //   provided that the user authenticates as the sender or recipient.
    // * A delete operation removes the message with specified message id from the
    //   bus, provided that the user authenticates as the sender or recipient.
    //
    // If authentication fails, (the user has not authenticated as the
    // sender or recipient) an all-zeroes record is returned in constant-time.
    // If the id does not exist, an all-zeroes record is returned in constant-time.
    //
    // There is further variation if the user-specified id is all zeroes.
    //
    // * If the user-specified msg_id is all zeroes, we return the first message if
    //   any that is in the bus for the user that authenticated with us.
    // * If the operation is read, that message remains in the bus.
    // * If the operation is delete, that message is deleted from the bus.
    // * If the operation is update, an error is returned. This scenario is not
    //   constant-time. The user can reliably avoid it by not using update with the
    //   all-zeroes message id.
    fn access_record(&mut self, query: &QueryRequest) -> Result<QueryResponse, QueryError> {
        let is_update_request = query.request_type.ct_eq(&3);
        let is_delete_request = query.request_type.ct_eq(&4);

        // Make the identity bytes aligned for faster testing later.
        let identity: A8Bytes<U32> = Aligned(
            <[u8; 32] as TryFrom<_>>::try_from(&query.auth_identity[..])
                .map_err(|_| QueryError::InvalidAuthIdentityLength(query.auth_identity.len(), 32))?
                .into(),
        );
        let (mut id, mut marshalled) = MarshalledRecord::new_from_proto(&query.record)?;
        let id_is_zero = id.ct_eq(&Default::default());

        if bool::from(id_is_zero & is_update_request) {
            return Err(QueryError::CannotUpdateZeroesEntry);
        }

        marshalled
            .get_timestamp_mut()
            .cmov(is_update_request, &self.current_timestamp);

        let mut result_record: A8Bytes<MessageBusValueSize> = Default::default();

        let mut message_omap_result_code = 0u32;
        let mut recipient_omap_result_code = 0u32;

        self.recipients_to_ids
            .access(marshalled.get_recipient(), |code, buffer| {
                recipient_omap_result_code = code;

                // For an update or delete query, we already know what record we want to modify
                // or delete. For a read query, we might have a valid id to
                // read, or not, in which case we search for the next one in the queue.
                let chunks: &mut [A8Bytes<U24>] = buffer.as_mut_aligned_chunks();
                for chunk in chunks.iter_mut() {
                    let (msg_id, timestamp): (&mut A8Bytes<U16>, &mut A8Bytes<U8>) = chunk.split();

                    let msg_id_is_zero = msg_id.ct_eq(&Default::default());
                    let timestamp_expired = (timestamp.as_ne_u64_slice()[0]
                        + self.message_time_to_live)
                        .ct_lt(&self.current_timestamp);

                    // If it's a query with a zero msg_id, and the current one we are looking at is
                    // not zero and is not expired, then change id to be this
                    // msg_id we are looking at now.
                    id.cmov(id_is_zero & !(msg_id_is_zero | timestamp_expired), &msg_id)
                }

                let mut delete = Choice::from(0);
                self.ids_to_messages
                    .access_and_remove(&id, |code, record| -> Choice {
                        message_omap_result_code = code;

                        // unsafe cast to layout compatible type to help with accessing layout T_T
                        let record: &mut MarshalledRecord = unsafe { core::mem::transmute(record) };

                        // We can give read and write access only if the authenticated identity
                        // matches the sender or the recipient.
                        let has_permission = record.get_sender().ct_eq(&identity)
                            | record.get_recipient().ct_eq(&identity);

                        // Check if the record is expired, if it is we will delete it now.
                        let timestamp_expired = (record.get_timestamp()
                            + self.message_time_to_live)
                            .ct_lt(&self.current_timestamp);

                        // We should return this record as long as the user has permission. (Read
                        // update and delete)
                        result_record.cmov(has_permission, record.as_ref());

                        // We should modify this record only if it is an update request, and the
                        // user has permission
                        record
                            .as_mut()
                            .cmov(has_permission & is_update_request, marshalled.as_ref());

                        // We should delete this record only if it is a delete request, and the user
                        // has permission, OR if the timestamp is expired.
                        delete = (has_permission & is_delete_request) | timestamp_expired;

                        delete.clone()
                    });

                delete = delete | message_omap_result_code.ct_eq(&OMAP_NOT_FOUND);

                // Now update the record in the recipient's table with what happened.
                // If it's an update, we have to update the timestamp.
                // If it's a delete (or not found), we should remove the corresponding record in
                // the recipient's table.
                let chunks: &mut [A8Bytes<U24>] = buffer.as_mut_aligned_chunks();
                for chunk in chunks.iter_mut() {
                    let (msg_id, timestamp): (&mut A8Bytes<U16>, &mut A8Bytes<U8>) = chunk.split();

                    // Test if the id of this entry is msg_id
                    let has_msg_id = msg_id.ct_eq(&id);

                    // If this has the message id of what we looked for, and it was deleted (or not
                    // found) in the other table, then delete the reference in
                    // this table also.
                    msg_id.cmov(has_msg_id & delete, &Default::default());
                    timestamp.cmov(has_msg_id & delete, &Default::default());
                }
            });

        // write a status code for the request, based on insertion_succeeds and omap
        // result codes
        //
        // If the recipient is invalid:
        // STATUS_CODE_INVALID_RECIPIENT
        //
        // If the message is not found
        // STATUS_CODE_NOT_FOUND

        // XXX: FIXME
        let mut status_code = STATUS_CODE_INTERNAL_ERROR;

        status_code.cmov(
            recipient_omap_result_code.ct_eq(&OMAP_INVALID_KEY),
            &STATUS_CODE_INVALID_RECIPIENT,
        );

        Ok(QueryResponse {
            record: MarshalledRecord::from(result_record).to_proto(&id),
            status_code,
        })
    }
}
