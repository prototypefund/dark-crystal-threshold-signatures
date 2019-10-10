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
    this.contribBuffers = {}
    this.threshold = threshold
    this.numMembers = numMembers
    this.groupSignatures = {}
  }

  initId (seed) {
    // TODO assert seed...
    assert(!this.sk, 'id already generated')
    this.id = seed
    this.sk = bls.secretKey()
    bls.hashToSecretKey(this.sk, Buffer.from([seed]))
    this.members[bls.secretKeyExport(this.sk)] = {}
  }

  addMember (secretKey) {
    this.members[secretKey] = this.members[secretKey] || {}
  }

  generateContribution () {
    assert(Object.keys(this.members).length === this.numMembers, `not enough member ids, ${this.numMembers} needed`)
    const { verificationVector, secretKeyContribution } = dkg.generateContribution(bls, Object.keys(this.members).map(k => bls.secretKeyImport(k)), this.threshold)
    this.vvec = verificationVector.map(v => bls.publicKeyExport(v)) // publish this publicly
    this.members[bls.secretKeyExport(this.sk)].vvec = this.vvec
    console.log('----')
    secretKeyContribution.forEach((contrib, i) => {
      const contribBuffer = bls.secretKeyExport(contrib)
      this.contribBuffers[Object.keys(this.members)[i]] = contribBuffer
    })
    this.recievedShares.push(this.contribBuffers[bls.secretKeyExport(this.sk)])
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
      const vvecsPointers = vvecs.map(vvec => vvec.map(v => bls.publicKeyImport(v)))
      this.groupVvec = dkg.addVerificationVectors(bls, vvecsPointers)
      this.groupPublicKey = this.groupVvec[0]
      this.groupPublicKeyExport = bls.publicKeyExport(this.groupPublicKey)
    }
  }

  recieveContribution (sk, keyContributionBuffer) {
    const keyContribution = bls.secretKeyImport(keyContributionBuffer)
    const verified = dkg.verifyContributionShare(bls, this.sk, keyContribution, this.members[sk].vvec.map(v => bls.publicKeyImport(v)))
    if (!verified) return false
    this.recievedShares.push(keyContribution)
    // if ((this.recievedShares.length === this.threshold) && !this.groupSecretKeyShare) { // this.members.length
    if ((this.recievedShares.length === Object.keys(this.members).length) && !this.groupSecretKeyShare) {
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
    const signature = bls.signatureExport(signaturePointer)
    const signatureObject = { signature, id: this.sk }
    this.signatures[hashOfMessage].push(signatureObject)
    this.messagesByHash[hashOfMessage] = message
    return { signature, hashOfMessage }
  }

  recieveSignature (signature, id, hashOfMessage) {
    this.signatures[hashOfMessage] = this.signatures[hashOfMessage] || []
    const signatureObject = { signature, id: this.idToSk[id] }
    // check we dont already have it
    if (this.signatures[hashOfMessage].indexOf(signatureObject) < 0) this.signatures[hashOfMessage].push(signatureObject)

    if ((this.signatures[hashOfMessage].length >= this.threshold) && (!this.groupSignatures[hashOfMessage])) {
      const groupSig = bls.signature()

      // console.log('signatures', Object.values(this.signatures[hashOfMessage]).map(s => Buffer.from(s.signature).toString('hex')+' '+s.id))

      const signatures = Object.values(this.signatures[hashOfMessage]).map(s => bls.signatureImport(bufferToInt8(s.signature))).slice(0, this.threshold)

      const signerIds = Object.values(this.signatures[hashOfMessage]).map(s => s.id).slice(0, this.threshold)
      console.log(signatures)
      console.log(signerIds)
      bls.signatureRecover(groupSig, signatures, signerIds)

      console.log('groupsig',Buffer.from(bls.signatureExport(groupSig)).toString('hex'))

      console.log('verify', groupSig, Buffer.from(bls.publicKeyExport(this.groupPublicKey)).toString('hex'), this.messagesByHash[hashOfMessage])

      console.log(bls.verify(groupSig, this.groupPublicKey, this.messagesByHash[hashOfMessage]))
// console.log(Object.values(this.idToSk).map(s => Buffer.from(bls.secretKeyExport(s)).toString('hex')))
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

function sha256 (message) {
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
