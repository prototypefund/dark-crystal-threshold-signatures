const bls = require('bls-lib')
const dkg = require('dkg')
const assert = require('assert')
const crypto = require('crypto')

var blsInitialised = false

module.exports = function (threshold, numMembers) { return new Member(threshold, numMembers) }
module.exports.blsInit = function (callback) {
  if (blsInitialised) return callback()
  bls.onModuleInit(() => {
    bls.init()
    blsInitialised = true
    callback()
  })
}

class Member {
  constructor (threshold, numMembers) {
    // assert(threshold) < n, > 1 etc
    this.recievedShares = []
    this.isReady = false
    this.vvecs = []
    this.members = {}
    this.signatures = {}
    this.messagesByHash = {}
    this.threshold = threshold
    this.numMembers = numMembers
    this.idToSk = {}
  }

  initId (seed) {
    // TODO assert seed...
    assert(!this.sk, 'id already generated')
    this.id = seed
    this.sk = bls.secretKey()
    bls.hashToSecretKey(this.sk, Buffer.from([seed]))
    this.members[this.sk] = {}
    this.idToSk[seed] = this.sk
  }

  addMember (seed) {
    // TODO: assert seed...
    const sk = bls.secretKey()
    bls.hashToSecretKey(sk, Buffer.from([seed]))
    this.members[sk] = { id: seed }
    this.idToSk[seed] = sk
  }

  generateContribution () {
    assert(Object.keys(this.members).length === this.numMembers, `not enough member ids, ${this.numMembers} needed`)
    const { verificationVector, secretKeyContribution } = dkg.generateContribution(bls, Object.keys(this.members), this.threshold)
    this.vvec = verificationVector.map(v => bls.publicKeyExport(v)) // publish this publicly
    this.members[this.sk].vvec = this.vvec
    this.contribBuffers = {}
    secretKeyContribution.forEach((contrib, i) => {
      // console.log(bls.secretKeyExport(contrib))
      const contribBuffer = int8ToBuffer(bls.secretKeyExport(contrib))
      this.contribBuffers[this.members[Object.keys(this.members)[i]].id] = contribBuffer // encrypt and send these to each member
    })
    this.recievedShares.push(this.contribBuffers[this.id])
    return {
      vvec: this.vvec,
      contrib: this.contribBuffers
    }
  }

  storeVerificationVector (memberId, vvec) {
    const sk = this.idToSk[memberId]
    this.members[sk].vvec = vvec
    var vvecs = []
    Object.keys(this.members).forEach((someMember) => {
      if (this.members[someMember].vvec) vvecs.push(this.members[someMember].vvec)
    })
    if (vvecs.length === Object.keys(this.members).length) {
      console.log('got enough vvecs')
      const vvecsPointers = vvecs.map(vvec => vvec.map(v => bls.publicKeyImport(v)))
      this.groupVvec = dkg.addVerificationVectors(bls, vvecsPointers)
      this.groupPublicKey = this.groupVvec[0]
    }
  }

  recieveContribution (memberId, keyContributionBuffer) {
    const sk = this.idToSk[memberId]
    const keyContribution = bls.secretKeyImport(bufferToInt8(keyContributionBuffer))
    // const verified = dkg.verifyContributionShare(bls, sk, keyContribution, this.members[sk].vvec)
    // if (!verified) return false
    this.recievedShares.push(keyContribution)

    console.log(this.recievedShares.length)
    if (this.recievedShares.length === this.threshold) { // this.members.length
      this.groupSecretKeyShare = dkg.addContributionShares(bls, this.recievedShares)
    }
    return true
  }

  sign (message) {
    // TODO: assert message...
    assert(this.groupSecretKeyShare, 'Group secret key share not yet complete')
    const signaturePointer = bls.signature()
    bls.sign(signaturePointer, this.groupSecretKeyShare, message)
    const hashOfMessage = sha256(message)
    this.signatures[hashOfMessage] = this.signatures[hashOfMessage] || []
    const signature = int8ToBuffer(bls.signatureExport(signaturePointer))
    const signatureObject = { signature, id: this.sk }
    this.signatures[hashOfMessage].push(signatureObject)
    this.messagesByHash[hashOfMessage] = message
    return { signature, hashOfMessage }
  }

  recieveSignature (signature, id, hashOfMessage) {
    this.signatures[hashOfMessage] = this.signatures[hashOfMessage] || []
    const signatureObject = { signature, id: this.idToSk[id] }
    // TODO: check we dont already have it
    this.signatures[hashOfMessage].push(signatureObject)
    if ((this.signatures[hashOfMessage].length >= this.threshold) && (!this.groupSignatures[hashOfMessage])) {
      const groupSig = bls.signature()
      const signatures = Object.values(this.signatures[hashOfMessage]).map(s => bls.signatureImport(bufferToInt8(s.signature)))
      const signerIds = Object.values(this.signatures[hashOfMessage]).map(s => s.id)
      bls.signatureRecover(groupSig, signatures, signerIds)
      this.groupSignatures[hashOfMessage] = bls.verify(groupSig, this.groupPublicKey, this.messagesByHash[hashOfMessage])
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

function sha256(message) {
  const hash = crypto.createHash('sha256')
  hash.update(message)
  return hash.digest('hex')
}

function bufferToInt8 (buf) {
  // TODO
  // return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
  return buf
}

function int8ToBuffer (intArray) {
  // TODO
  return intArray
}
