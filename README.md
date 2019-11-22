# threshold-signatures

**Work in progress**

This is class providing group threshold signatures using distributed key generation.

Uses [bls-wasm](https://github.com/herumi/bls-wasm) and [a fork of dfinity/dkg](https://gitlab.com/dark-crystal/dkg) (not yet published to npm)

## API

`const ThresholdSig = require('.')`

### `ThresholdSig.blsInit(callback)`

`callback` is called when the bls module has initialised. This needs to be done before any cryptographic operations can take place.

### `const member = ThresholdSig(threshold, numMembers)`

Returns a `Member` instance with the following methods:

### `const id = member.initId(seed)`

Initialise the member's id from a seed. Returns the id as a hex encoded string. `seed` can be a buffer or a number.

### `member.addMember(id)`

Register the id of another member. `id` should be a hex encoded string output from `initId`.
Share contributions (the next step) cannot be generated until the ids of all other members have been received.

### `const { vvec, contrib } = member.generateContribution()`

Generate a verification vector and share contributions for each other member.
- `vvec` is an array of hex encoded strings.  This should be published publicly.
- `contrib` is an object, mapping hex encoded member ids to share contributions.  Each share contribution should be send privately to the respective member.

### `member.storeVerificationVector(id, vvec) 

Store the verification vector of another member of the given id. 

When all verification vectors have been collected, a verification vector for the group will be computed and stored in `member.groupVvec`, and the group public key will be computed and stored in `member.groupPublicKeyExport`.


### `const received = member.recieveContribution(id, contribution)`

Store a key contribution from the given member id.  The contribution will be verified against that members verification vector.
Returns true if the contribution could be verified and stored, false otherwise.
When all contributions from other members have been received, a group secret key-share, individual to each member, will be computed and stored in `member.groupSecretKeyShare`.  Only when this is done can messages be group signed.

### `const { signature, message } = member.sign(message)`

Sign a message. The resulting `signature` will be a hex encoded string.  This must be sent to other co-signers.

### `receiveSignature(signature, id, message)` 

Record a received signature from another member for the given message.  When the threshold number of signatures for that message have been received, the group signature will be aggregated and stored at `member.groupSignatures[message]`.  If the signature cannot be validated with the group's public key, this value will be `false` and the signature not stored.

## Not yet implemented:

### `member.saveState()`

Save all keys and signatures to disk.

### `member.loadState()`

Load all keys and signatures from disk.

### `member.clearState()`

Clear all keys and signatures from memory.
