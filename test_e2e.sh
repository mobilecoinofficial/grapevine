#!/bin/bash
#
# This is an end-to-end test of the compiled binaries and enclaves.
#
# Create a mc-bomb-server in the background.
# Then attempt to create, read, update, and delete messages, using mc-bomb-client.

set -e

: "${CARGO_TARGET_DIR:=../target/}"

if [ ! -f "$CARGO_TARGET_DIR/debug/mc-bomb-server" ]; then
    echo "Missing mc-bomb-server, needs cargo build"
    exit 1
fi

if [ ! -f "$CARGO_TARGET_DIR/debug/mc-bomb-client" ]; then
    echo "Missing mc-bomb-client, needs cargo build"
    exit 1
fi

my_exit() {
    set +x
    [ "$pid" ] && kill "$pid" || true
}
trap my_exit EXIT INT HUP TERM

failure() {
  local lineno=$1
  local msg=$2
  echo "Failed at line $lineno: $msg"
}
trap 'failure ${LINENO} "$BASH_COMMAND"' ERR

assert_eq() {
  local expected="$1"
  local actual="$2"
  local msg="${3-}"

  if [ "$expected" == "$actual" ]; then
    return 0
  else
    echo "Expected ${expected} == ${actual}"
    return 1
  fi
}

export MC_LOG=debug
export MC_URI=insecure-mc-bomb://0.0.0.0:3229
export MC_CLIENT_RESPONDER_ID=0.0.0.0:3229
export MC_CLIENT_LISTEN_URI=${MC_URI}
export MC_IAS_API_KEY="0000000000000000000000000000000000000000000000000000000000000000"
export MC_IAS_SPID="00000000000000000000000000000000"

export SECRET1="32159c7ae78c0d66ca2d9f9f956e42d51e1f0677fe83a1872d99dc366550e20a"
export PUBLIC1="287eecba4a53288234c49384fd533ec6e3d8438ce259a0a5476c2af9b07c3a35"
export SECRET2="8ebae2cc8178e403b6b661496c474dd3a4404b764a838392cd3ad704ee08ca00"
export PUBLIC2="ee093e113a3bce46c07073c3906fec7768acb116afe65e55b712031f445dd53d"
export SECRET3="b4c11289a15fbe8c3a7ef7ed7034760ee48cf971ecd0f5b359ef745c1442a904"
export PUBLIC3="14cf7f67de11de522a061d126eda3c7c7a7f640556b9aabb849b00edc9053567"

cd "$CARGO_TARGET_DIR/debug"

./mc-bomb-server &
pid=$!

# Wait 60 seconds for the server to wake up
for PORT in 3229; do
  for _unused in $(seq 0 60); do
    if ss -l | grep -q ":$PORT"; then break; else sleep 1; fi;
  done
done

set -e

# Switch to user 1
export MC_SECRET_KEY=${SECRET1}

# We should not have any messages yet
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Send a message to ourself
CREATE_RESP1=$(./mc-bomb-client create --recipient ${PUBLIC1} --message "baseball is overrated")
assert_eq "$(echo "$CREATE_RESP1" | jq -r .record.message)" "baseball is overrated"
assert_eq "$(echo "$CREATE_RESP1" | jq -r .record.recipient)" "${PUBLIC1}"

MSG_ID1=$(echo "$CREATE_RESP1" | jq -r .record.msg_id)

# Try to read again, we should see the message
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID1"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC1}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "baseball is overrated"

# Reading that specific id should produce the same message
RESP=$(./mc-bomb-client read --msg-id $MSG_ID1)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID1"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC1}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "baseball is overrated"

# Reading a junk id should produce the empty message
RESP=$(./mc-bomb-client read --msg-id "ffffffffffffffffffffffffffffffff")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Send a message to user 2
CREATE_RESP2=$(./mc-bomb-client create --recipient ${PUBLIC2} --message "frisbee golf is the sport of kings")
assert_eq "$(echo "$CREATE_RESP2" | jq -r .record.message)" "frisbee golf is the sport of kings"
assert_eq "$(echo "$CREATE_RESP2" | jq -r .record.recipient)" "${PUBLIC2}"

MSG_ID2=$(echo "$CREATE_RESP2" | jq -r .record.msg_id)

# We should be able to read it by message id
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID2")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID2"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC2}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "frisbee golf is the sport of kings"

# We should see the first message when we don't give a message id, the second message isn't in our mailbox
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID1"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC1}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "baseball is overrated"

# Switch to user 2
export MC_SECRET_KEY=${SECRET2}

# We should see the second message, because it's in our mailbox
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID2"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC2}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "frisbee golf is the sport of kings"

# Reading a junk id should produce the empty message
RESP=$(./mc-bomb-client read --msg-id "ffffffffffffffffffffffffffffffff")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Reading a msg_id 1 should produce the empty message, since we don't have permission to see it
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID1")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# We should be able to update the second message. The response will contain the message from before the update.
RESP=$(./mc-bomb-client update --msg-id "$MSG_ID2" --recipient "${PUBLIC2}" --message "frisbee golf? ha!")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID2"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC2}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "frisbee golf is the sport of kings"

# Switch to user 3
export MC_SECRET_KEY=${SECRET3}

# We should not have any messages yet
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# We should not be able to see msg 1
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID1")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# We should not be able to see msg 2
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID2")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Switch to user 1
export MC_SECRET_KEY=${SECRET1}

# Message 1 is still in our mailbox
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID1"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC1}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "baseball is overrated"

# Deleting the message returns the message in the response
# "Blind deleting" works
RESP=$(./mc-bomb-client delete)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID1"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC1}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "baseball is overrated"

# Message 1 is no longer in our mailbox
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Reading message id 2 produces the updated message
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID2")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID2"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC2}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "frisbee golf? ha!"

# Switch to user 2
export MC_SECRET_KEY=${SECRET2}

# We should see the updated second message, because it's in our mailbox
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID2"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC2}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "frisbee golf? ha!"

# We should be able to delete the message by message id
RESP=$(./mc-bomb-client delete --msg-id "$MSG_ID2")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID2"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC2}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "frisbee golf? ha!"

# Message 2 is no longer in our mailbox
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Send a message to user 1
CREATE_RESP3=$(./mc-bomb-client create --recipient ${PUBLIC1} --message "back in my day, youngsters would rob the Kwik-E-Mart for sport!")
assert_eq "$(echo "$CREATE_RESP3" | jq -r .record.message)" "back in my day, youngsters would rob the Kwik-E-Mart for sport!"
assert_eq "$(echo "$CREATE_RESP3" | jq -r .record.recipient)" "${PUBLIC1}"

MSG_ID3=$(echo "$CREATE_RESP3" | jq -r .record.msg_id)

# Switch to user 3
export MC_SECRET_KEY=${SECRET3}

# We should not have any messages yet
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# We should not be able to see msg 1
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID1")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# We should not be able to see msg 2
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID2")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# We should not be able to see msg 3
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID3")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Switch to user 1
export MC_SECRET_KEY=${SECRET1}

# Message 1 is still in our mailbox
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID3"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC1}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "back in my day, youngsters would rob the Kwik-E-Mart for sport!"

# Message 2 is no longer visible
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID2")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Send a message to user 2
CREATE_RESP4=$(./mc-bomb-client create --recipient ${PUBLIC2} --message "grandpa, there was no Kwik-E-Mart when you were young!")
assert_eq "$(echo "$CREATE_RESP4" | jq -r .record.message)" "grandpa, there was no Kwik-E-Mart when you were young!"
assert_eq "$(echo "$CREATE_RESP4" | jq -r .record.recipient)" "${PUBLIC2}"

MSG_ID4=$(echo "$CREATE_RESP4" | jq -r .record.msg_id)

# Switch to user 2
export MC_SECRET_KEY=${SECRET2}

# Message 4 is in our mailbox
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID4"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC2}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "grandpa, there was no Kwik-E-Mart when you were young!"

# Try to delete message 3 as the sender
RESP=$(./mc-bomb-client delete --msg-id "$MSG_ID3" --recipient "$PUBLIC1")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID3"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC1}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "back in my day, youngsters would rob the Kwik-E-Mart for sport!"

# Delete should work, it should no longer be visible
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID3")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Our mailbox should still have message 4
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID4"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC2}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "grandpa, there was no Kwik-E-Mart when you were young!"

# Switch to user 3
export MC_SECRET_KEY=${SECRET3}

# We should still not have any messages
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# We should not be able to see msg 1
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID1")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# We should not be able to see msg 2
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID2")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# We should not be able to see msg 3
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID3")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# We should not be able to see msg 4
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID4")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Switch to user 1
export MC_SECRET_KEY=${SECRET1}

# Our inbox is now empty
RESP=$(./mc-bomb-client read)
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "00000000000000000000000000000000"
assert_eq "$(echo "$RESP" | jq -r .record.message)" ""

# Message 4 is still visible
RESP=$(./mc-bomb-client read --msg-id "$MSG_ID4")
assert_eq "$(echo "$RESP" | jq -r .record.msg_id)" "$MSG_ID4"
assert_eq "$(echo "$RESP" | jq -r .record.recipient)" "${PUBLIC2}"
assert_eq "$(echo "$RESP" | jq -r .record.message)" "grandpa, there was no Kwik-E-Mart when you were young!"

echo "*** CRUD e2e TESTS PASSED ***"
