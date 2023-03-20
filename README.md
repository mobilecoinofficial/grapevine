MobileCoin Basic Oblivious Message Broker
=========================================

This is a prototype oblivious message broker, which allows posting messages for
a recipient, and searching for messages, using a CRUD API.

Let's suppose you have the following situation.

* You have a mobile app, and you want Alice's client wants to pass a message to Bob's client.
* Following with standard practices, Alice does not make a direct p2p connection
  to Bob, for a lot of reasons. Instead, Alice writes her message to a backend service
  (which is sometimes called a "message broker")
  with a tag indicating that the message is intended for Bob.
* Later, Bob is able to discover and download the message from the backend service.
  This way the message can be delivered asynchronously even if Alice and Bob do not have
  their apps open at the exact same time.

However, you are concerned about privacy impacts of this arrangement. You, the service
operator, can see when Alice is writing a message to Bob -- you likely can see Alice's
IP when she reaches out, and she may have some kind of auth token that you use to ensure
she's a real user and prevent DOS attacks, which identifies her when she makes a connection.
And you can see that it's for Bob because of the tag.

(If the messages are not tagged for the recipient, there might be an alternative where Bob downloads
all messages from the server and trial decrypts them. However, this likely doesn't scale.)

The service implemented here can be used as part of a solution to try to resolve these issues:

* The pending messages are stored in SGX encrypted memory and not in a "transparent" message bus or db.
* When Alice writes a message to the oblivious broker, you (the service operator) cannot see what
  she wrote, because it is sent over an encrypted, attested channel, and it doesn't leave the encrypted memory.
* You also cannot dump the entire message set. The broker will only give you Bob's messages
  if you can sign a challenge with Bob's private key.
* When Bob searches for a message or messages, you don't know for sure if he found anything, or
  which exact encrypted messages he downloaded. This prevents you from "following the bytes" and connecting
  the message from Alice to Bob.

Moreover, the service attempts to resist active attacks which would allow the service operator to undermine these
goals. For instance,

* Suppose Alice creates a message.
* If the untrusted service operator then systematically dumps all messages from the broker, they can see what new
  message was created, because they can see what was there before and what was there after.
* Suppose Bob receives the message and then deletes it.
* If the untrusted service operator then systematically dumps all messages from the broker, they can see what
  message was deleted.
* The service operator infers that Alice sent a message to Bob.

To prevent these attacks, read access to the messages is authenticated. Every message has a sender and recipient public key
associated to it, and you can only see or interact with the message if you can sign a challenge value with the private key.
(This approach to enforcement also precludes the ability to e.g. dump all the messages to disk.)

The service generally attempts to be oblivious about:

* If a message was created, which one was created.
* If a message was read, updated, or deleted, which is the case, and avoid revealing anything about the message or
  the success or failure of these operations (except in API-misuse scenarios).

Limits
------

The broker has a maximum capacity for messages which cannot be exceeded. This could be reasonably configured
to be close to the RAM limits of the machine.

The broker also imposes a limit on how many messages can be in-flight destined for a particular user.
This limit is 62 at time of writing, and could be changed by adjusting compile-time constants, with some
performance impact.

Currently, in the use-cases that we envision, sending someone more than 62 concurrent messages is likely a malicious behavior.
We expect that ultimately users will have to provide an auth token to talk to this service at all, and this can be a vehicle
to rate limit how quickly users can create messages.

Message expiry
--------------

To ensure that messages leave the broker after some time, messages enter the broker's storage with an
approximate timestamp, and when a certain expiry period has passed, they are deleted in
the enclave. This expiry period is a command-line argument to the broker.

The timestamps that the enclave uses to make these determinations come from the untrusted service,
and not from any trusted service within the enclave. It is assumed that the node operator
wants to provide the service and wants messages to expire after some time so that the storage is
not eventually exhausted. We seek to establish a security property -- tampering with these timestamps
does not enable the node operator to infer anything about sender / recipient linkage and undermine
the privacy properties of the message broker.

Note: In the MVP we didn't fully implement eviction of expired messages from the hashmap.

Durable messages
----------------

In some applications, it might be desired that Alice and Bob can always recover their historical
messages that they sent and received. It is recommended that they do this by writing encrypted
records (which only they read) to another database, separate from this broker, as making a completely
durable oblivious message broker is a far more complex engineering problem. (This is the problem
statement for MobileCoin Fog, and will require many more enclaves and much more operational complexity.)

It is out of scope to make this message broker itself perform permanent storage of its in-transit contents.

Think of this as closer to "oblivious redis" than "oblivious kafka".

If you think you need oblivious kafka for your use-case,
you probably actually need an adapted version of MobileCoin Fog (fog-ingest and fog-view working together)
and not this service.

High availability
-----------------

For high availability, the right thing is likely that the message broker should be able to perform node-to-node
attestation with peers and replicate the messages to them. (In the MVP we do not plan to do this, however.)

Overview
========

This repo contains both a grpc service (in rust) and an enclave (in rust). You can build both with `cargo build`.

Configuring and starting it should be relatively straightforward, see `./mc-bomb-server --help`.

You can study the example client to get started, or you can start by referring to the API docs below.

Message
-------

Each messsage is conceptually 1024 bytes with the following layout:

|----------|--------------- | ----------------- | --------- | --------- |
| id       | sender_pub_key | recipient_pub_key | timestamp | payload   |
| 16 bytes | 32 bytes       | 32 bytes          | 16 bytes  | 936 bytes |
|----------|--------------- | ----------------- | --------- | --------- |

(Alternative configuration is possible at compile-time, for example, we could increase message
size to 2048 bytes and have a payload of almost 2kb)

The pubkey fields are compressed ristretto curve points. (We could compile it to use ed25519 instead though.)

The timestamp is an unsigned 64-bit integer number of seconds UTC since the unix epoch.

The payload is not interpreted by the broker, but the other fields are. You must provide excatly e.g. 936 bytes in 1024 byte mode.
This is required in order for the broker to establish its security goals.

We suggest that you should read and write "framed protobuf" to the payload field. The first 2 bytes can indicate
how many of the 934 remaining bytes are data, and the rest can be the protobuf bytes, followed by zeroes.

Note: This raw-bytes payload is not as nice as many web-service APIs, which typically assign semantics to all parts of their requests
and not just treat things as dumb bytes. But, a fixed size in bytes is needed for ORAM to work. By allowing the API to be dumb bytes,
we allow clients to decide the semantics and make this implementation able to serve many use-cases without enclave changes.

The id bytes are any 16 bytes of your choosing, except all zeroes. It is suggested that they can be random.
An all-zeroes value is not a valid id.

API
---

The broker allows you to perform CRUD operations:

* Create: You may upload a message. The timestamp you specify is ignored, the broker assigns a timestamp.
  You must authenticate with the service by signing a challenge value with the sender key (more on this below).
* Read: You must authenticate with the service by signing a challenge value with the recipient key (more on this below).
  You can either request specific IDs that you wish to read, or request the service to give you all ID's associated to you.
* Update: You must authenticate with the service by signing a challenge value with the sender or recipient key.
  You specify a complete message, and if a matching id field is found, that message will be updated, and its timestamp
  updated.
* Delete: You must authenticate with the service by signing a challenge value with either the sender OR recipient key.
  You can then specify id of the message that you wish to delete from the broker.

To communicate with the broker, you need to use mobilecoin's standard method for creating attested connections to enclaves.

1. First you will try to create an attested connection. On success, you will end up with an instance
of `mc-noise` cipher which you can use to encrypt messages for the enclave.
2. Then, look at the `client_request` API of the `mc-bomb-api` proto file. You will encrypt a `QueryRequest` object for the
   enclave, proudcing an `attest::Message` object which you will attach to that API. When you get a response, you can decrypt it
   using your cipher object, and then try to decode the `QueryResponse` object and interpret it.
   
For more detailed info about `QueryRequest` and `QueryResponse`, see the `bomb.proto` file comments.

Authentication
--------------

The idea when authenticating with the broker is:

* The challenge value is determined by an RNG whose seed is created when the attested connection is created -- the server sends this back to you with
  the successful auth response. Each time you create a request over this channel, you should pull 32 bytes of entropy from this RNG, which will be the challenge value.
* Then you should sign those challenge bytes using your ristretto private key. This is done using Mobilecoin's standard deterministic Schnorrkel sig.

All of the query requests require some form of authentication. You must always pull this 32 byte challenge value, before encrypting your request using the noise cipher.
The server will simliarly always pull this challenge value before attempting to decrypt your request, in order to remain in-sync with you.

See the example client for more details about this.

See the `mc-crypto-keys` crate for details about this signature scheme. You need to call the `sign_schnorrkel` function on `RistrettoPrivate` (or some wrapper of this).

HTTP interface?
---------------

If you need an HTTP interface, it is recommended to use `go-grpc-gateway`, build it against the `bomb.proto`, and deploy it alongside this service.
