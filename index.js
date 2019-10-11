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
    this.recievedShares = []
    this.vvecs = []
    this.members = {}
    this.signatures = {}
    // this.messagesByHash = {}
    this.contribBuffers = {}
    this.threshold = threshold
    this.numMembers = numMembers
    this.groupSignatures = {}
  }

  initId (seed) {
    // TODO assert seed...
    assert(!this.sk, 'id already generated')
    this.id = seed
    this.sk = new bls.SecretKey()
    this.sk.setHashOf(Buffer.from([seed]))
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
      const contribBuffer = contrib.serializeToHexStr()
      this.contribBuffers[Object.keys(this.members)[i]] = contribBuffer
      contrib.clear()
    })
    this.recievedShares.push(bls.deserializeHexStrToSecretKey(this.contribBuffers[this.skHex]))
    return {
      vvec: this.vvec,
      contrib: this.contribBuffers
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
      // console.log(vvecsPointers)
      this.groupVvec = dkg.addVerificationVectors(vvecsPointers)
      this.groupPublicKey = this.groupVvec[0]
      this.groupPublicKeyExport = this.groupPublicKey.serializeToHexStr()
    }
  }

  recieveContribution (sk, keyContributionStr) {
    const keyContribution = bls.deserializeHexStrToSecretKey(keyContributionStr)
    const verified = dkg.verifyContributionShare(bls, this.sk, keyContribution, this.members[sk].vvec.map(v => bls.deserializeHexStrToPublicKey(v)))
    if (!verified) return false
    this.recievedShares.push(keyContribution)
    // if ((this.recievedShares.length === this.threshold) && !this.groupSecretKeyShare) { // this.members.length
    if ((this.recievedShares.length === Object.keys(this.members).length) && !this.groupSecretKeyShare) {
      this.groupSecretKeyShare = dkg.addContributionShares(this.recievedShares)
    }
    return true
  }

  sign (message) {
    // TODO: assert message...
    assert(this.groupSecretKeyShare, 'Group secret key share not yet complete')
    const signaturePointer = this.groupSecretKeyShare.sign(message)
    // const pk = bls.publicKey()
    // bls.getPublicKey(pk, this.groupSecretKeyShare)
    // console.log('sigtest:', bls.verify(signaturePointer, pk, message))
    this.signatures[message] = this.signatures[message] || []
    const signature = signaturePointer.serializeToHexStr()
    const signatureObject = { signature, id: this.skHex }
    this.signatures[message].push(signatureObject)
    return { signature, message }
  }

  recieveSignature (signature, sk, message) {
    this.signatures[message] = this.signatures[message] || []
    const signatureObject = { signature, id: sk }
    // check we dont already have it (need to compare objects)
    // if (this.signatures[hashOfMessage].indexOf(signatureObject) < 0)
    this.signatures[message].push(signatureObject)

    if ((this.signatures[message].length >= this.threshold) && (!this.groupSignatures[message])) {
      const groupSig = new bls.Signature()

      // console.log('signatures', Object.values(this.signatures[hashOfMessage]).map(s => Buffer.from(s.signature).toString('hex')+' '+s.id))

      var signatures = []
      var signerIds = []
      this.signatures[message].forEach((sigObject) => {
        signatures.push(bls.deserializeHexStrToSignature(sigObject.signature))
        signerIds.push(bls.deserializeHexStrToSecretKey(sigObject.id))
      })

      // console.log(signatures)
      // console.log(signerIds)
      groupSig.recover(signatures, signerIds)

      // console.log(this.groupPublicKey.verify(groupSig, message))
      this.groupSignatures[message] = this.groupPublicKey.verify(groupSig, message)
        ? groupSig
        : false
    }
  }

  saveState () {
    //this.signatures
    //Buffer.from(bls.signatureExport())
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
