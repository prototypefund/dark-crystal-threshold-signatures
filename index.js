const bls = require('bls-wasm')
const dkg = require('dkg')
const assert = require('assert')
const crypto = require('crypto')

var blsInitialised = false

module.exports = function (threshold, numMembers) { return new Member(threshold, numMembers) }
module.exports.blsInit = function (callback) {
  if (blsInitialised) return callback()
  bls.init().then(() => {
    blsInitialised = true
    callback()
  })
}

class Member {
  constructor (threshold, numMembers) {
    assert(numMembers > 1, 'Need at least two members')
    assert(threshold <= numMembers, 'Threshold must not be greater than number of members')
    this.receivedShares = []
    this.receivedSharesFrom = []
    this.vvecs = []
    this.members = {}
    this.signatures = {}
    // this.messagesByHash = {}
    this.contribs = {}
    this.threshold = threshold
    this.numMembers = numMembers
    this.groupSignatures = {}
  }

  initId (seed) {
    // TODO assert seed...
    assert(!this.sk, 'id already generated')
    this.id = seed
    this.sk = new bls.SecretKey()
    if (typeof seed === 'number') seed = Buffer.from([seed])
    this.sk.setHashOf(seed)
    this.skHex = this.sk.serializeToHexStr()
    this.members[this.skHex] = {}
    return this.skHex
  }

  addMember (secretKey) {
    this.members[secretKey] = this.members[secretKey] || {}
    // this.members[secretKey].sk = secretKey
  }

  generateContribution () {
    assert(Object.keys(this.members).length === this.numMembers, `not enough member ids, ${this.numMembers} needed`)
    const { verificationVector, secretKeyContribution } = dkg.generateContribution(bls, Object.keys(this.members).map(k => bls.deserializeHexStrToSecretKey(k)), this.threshold)
    this.vvec = verificationVector.map(v => v.serializeToHexStr()) // publish this publicly
    // verificationVector.forEach(v => bls.free(v))
    this.members[this.skHex].vvec = this.vvec
    secretKeyContribution.forEach((contrib, i) => {
      const contribHex = contrib.serializeToHexStr()
      this.contribs[Object.keys(this.members)[i]] = contribHex
      contrib.clear()
    })
    this.receivedShares.push(bls.deserializeHexStrToSecretKey(this.contribs[this.skHex]))
    return {
      vvec: this.vvec,
      contrib: this.contribs
    }
  }

  storeVerificationVector (sk, vvec) {
    this.members[sk].vvec = vvec
    var vvecs = []
    Object.keys(this.members).forEach((someMember) => {
      if (this.members[someMember].vvec) vvecs.push(this.members[someMember].vvec)
    })
    if (vvecs.length === Object.keys(this.members).length) {
      const vvecsPointers = vvecs.map(vvec => vvec.map(v => bls.deserializeHexStrToPublicKey(v)))
      this.groupVvec = dkg.addVerificationVectors(vvecsPointers)
      this.groupPublicKey = this.groupVvec[0]
      this.groupPublicKeyExport = this.groupPublicKey.serializeToHexStr()
    }
  }

  receiveContribution (sk, keyContributionStr) {
    assert(typeof keyContributionStr === 'string', 'key contribution should be a hex encoded string')

    // check we dont already have it from that sk. (cant assume bls wont give us a new pointer for the same contrib)
    if (this.receivedSharesFrom.includes(sk)) return true

    const keyContribution = bls.deserializeHexStrToSecretKey(keyContributionStr)
    const verified = dkg.verifyContributionShare(
      bls,
      this.sk,
      keyContribution,
      this.members[sk].vvec.map(v => bls.deserializeHexStrToPublicKey(v))
    )
    if (!verified) return false
    this.receivedShares.push(keyContribution)
    this.receivedSharesFrom.push(sk)
    // if ((this.receivedShares.length === this.threshold) && !this.groupSecretKeyShare) { // this.members.length
    if ((this.receivedShares.length === Object.keys(this.members).length) && !this.groupSecretKeyShare) {
      this.groupSecretKeyShare = dkg.addContributionShares(this.receivedShares)
    }
    return true
  }

  sign (message) {
    // TODO: assert message...
    // TODO: return hash of message
    assert(this.groupSecretKeyShare, 'Group secret key share not yet complete')
    const signaturePointer = this.groupSecretKeyShare.sign(message)
    // const pk = bls.publicKey()
    // bls.getPublicKey(pk, this.groupSecretKeyShare)
    this.signatures[message] = this.signatures[message] || []
    const signature = signaturePointer.serializeToHexStr()
    const signatureObject = { signature, id: this.skHex }
    this.signatures[message].push(signatureObject)
    return { signature, message }
  }

  receiveSignature (signature, sk, message) {
    assert(typeof signature === 'string', 'signature must be a string')
    assert(typeof sk === 'string', 'id must be a string')
    assert(message, 'Message not given')

    this.signatures[message] = this.signatures[message] || []
    const signatureObject = { signature, id: sk }
    // check we dont already have it (need to compare objects)
    // if (this.signatures[hashOfMessage].indexOf(signatureObject) < 0)
    if (!this.signatures[message].find(o => o.id === sk)) this.signatures[message].push(signatureObject)

    if ((this.signatures[message].length >= this.threshold) && (!this.groupSignatures[message])) {
      const groupSig = new bls.Signature()

      var signatures = []
      var signerIds = []

      this.signatures[message].forEach((sigObject) => {
        signatures.push(bls.deserializeHexStrToSignature(sigObject.signature))
        signerIds.push(bls.deserializeHexStrToSecretKey(sigObject.id))
      })

      groupSig.recover(signatures, signerIds)
      this.groupSignatures[message] = this.groupPublicKey.verify(groupSig, message)
        ? groupSig
        : false
    }
  }

  saveState () {
    // this.signatures
    // Buffer.from(bls.signatureExport())
  }

  loadState () {

  }

  clearState () {

  // bls.free(pk1)
  // bls.free(pk2)
  // bls.freeArray(groupsVvec)
  // bls.freeArray(newGroupsVvec)
  // members.forEach(m => {
  //   bls.free(m.secretKeyShare)
  //   bls.free(m.id)
  // })
  }
}

function sha256 (message) {
  const hash = crypto.createHash('sha256')
  hash.update(message)
  return hash.digest('hex')
}

function int8ToHex (ta) {
  return Buffer.from(ta).toString('hex')
}

function hexToInt8 (h) {
  return bufferToInt8Array(Buffer.from(h, 'hex'))
}

function bufferToInt8Array (a) {
  const ta = new Int8Array(a.length)
  for (var i = 0; i < a.length; i++) {
    ta[i] = conv(a[i])
  }
  return ta

  function conv (i) {
    return (i > 127) ? i - 256 : i
  }
}
