const bls = require('bls-lib')
const dkg = require('dkg')
const assert = require('assert')
const crypto = require('crypto')

module.exports = function (threshold, numMembers) { return new Member(threshold, numMembers) }

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
    this.members[sk] = {}
    this.idToSk[seed] = sk
  }

  generateContribution () {
    assert(Object.keys(this.members).length === this.numMembers, `not enough member ids, ${this.numMembers} needed`)
    const { verificationVector, secretKeyContribution } = dkg.generateContribution(bls, Object.keys(this.members), this.threshold)
    this.vvec = verificationVector // publish this publicly
    secretKeyContribution.forEach((contrib, i) => {
      this.members[Object.keys(this.members)[i]].contrib = contrib // encrypt and send these to each member
    })
    return this.vvec
  }

  storeVerificationVector (memberId, vvec) {
    const sk = this.idToSk[memberId]
    this.members[sk].vvec = vvec
    var vvecs = []
    Object.keys(this.members).forEach((someMember) => {
      if (this.members[someMember].vvec) vvecs.push(this.members[someMember].vvec)
    })
    if (vvecs.length === this.members.length) {
      this.groupVvec = dkg.addVerificationVectors(bls, vvecs)
      this.groupPublicKey = this.groupVvec[0]
    }
  }

  recieveContribution (memberId, keyContribution) {
    const sk = this.idToSk[memberId]
    const verified = dkg.verifyContributionShare(bls, sk, keyContribution, this.members[sk].vvec)
    if (!verified) return false
    this.recievedShares.push(keyContribution)

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
    const signature = Buffer.from(bls.signatureExport(signaturePointer))
    const signatureObject = { signature, id: this.sk }
    this.signatures[hashOfMessage].push(signatureObject)
    this.messagesByHash[hashOfMessage] = message
    return { signature, hashOfMessage }
  }

  recieveSignature (signature, id, hashOfMessage) {
    this.signatures[hashOfMessage] = this.signatures[hashOfMessage] || []
    const signatureObject = { signature, id: this.idToSk(id) }
    // TODO: check we dont already have it
    this.signatures[hashOfMessage].push(signatureObject)
    if ((this.signatures[hashOfMessage].length >= this.threshold) && (!this.groupSignatures[hashOfMessage])) {
      const groupSig = bls.signature()
      const signatures = Object.values(this.signatures[hashOfMessage]).map(s => bls.signatureImport(s.signature.buffer))
      const signerIds = Object.values(this.signatures[hashOfMessage]).map(s => s.id)
      bls.signatureRecover(groupSig, signatures, signerIds)
      this.groupSignatures[hashOfMessage] = bls.verify(groupSig, this.groupPublicKey, this.messagesByHash[hashOfMessage])
        ? groupSig
        : false
    }
  }

  ready (callback) {
    if (this.isReady === true) return callback()
    bls.onModuleInit(() => {
      bls.init()
      this.isReady = true
      callback()
    })
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
