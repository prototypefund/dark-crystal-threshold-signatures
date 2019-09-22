const bls = require('bls-lib')
const dkg = require('./')
const assert = require('assert')

module.exports = function (threshold, numMembers) { return new Member(threshold, numMembers) }

class Member {
  constructor (threshold, numMembers) {
    // assert(threshold) < n, > 1 etc
    this.recievedShares = []
    this.isReady = false
    this.vvecs = []
    this.members = {}
    this.signatures = {}
    this.threshold = threshold
    this.numMembers = numMembers
    this.idToSk = {}
  }

  initId (seed) {
    // TODO assert seed...
    assert(!this.sk, 'id already generated')
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
    const { verificationVector, secretKeyContribution } = dkg.generateContribution(bls, Object.keys(this.members), this.threshold)
    this.vvec = verificationVector // publish this publicly
    secretKeyContribution.forEach((sk, i) => {
      this.members[Object.keys(this.members)[i]] = sk // encrypt and send these to each member
    })
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
      this.groupSecretKeyShare = dkg.addContributionShares(bls, member.recievedShares)
    }
    return true
  }

  sign (message) {
    // TODO: assert message...
    assert(this.groupSecretKeyShare, 'Group secret key share not yet complete')
    const signature = bls.signature()
    bls.sign(signature, this.groupSecretKeyShare, message)
    const hashOfMessage = hash(message)
    this.signatures[hashOfMessage] = this.signatures[hashOfMessage] || []
    const signatureObject = { signature, id: this.sk }
    this.signatures[hashOfMessage].push(signatureObject)
    return signature
  }

  recieveSignature (signature, id, hashOfMessage) {
    this.signatures[hashOfMessage] = this.signatures[hashOfMessage] || []
    const signatureObject = { signature, id: this.idToSk(id) }
    // TODO: check we dont already have it
    this.signatures[hashOfMessage].push(signatureObject)
    if ((this.signatures[hashOfMessage].length >= this.threshold) && (!this.groupSignatures[hashOfMessage])) {
      const groupSig = bls.signature()
      const signatures = Object.values(this.signatures[hashOfMessage]).map(s => s.signature)
      const signerIds = Object.values(this.signatures[hashOfMessage]).map(s => s.id)
      bls.signatureRecover(groupSig, signatures, signerIds)
      // bls.verify(groupSig, this.groupPublicKey, message) ? :
      this.groupSignatures[hashOfMessage] = groupSig
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

  // we can also use the groups verification vector to derive any of the members
  // public key
  const member = members[4]
  const pk1 = bls.publicKey()
  bls.publicKeyShare(pk1, groupsVvec, member.id)

  const pk2 = bls.publicKey()
  bls.getPublicKey(pk2, member.secretKeyShare)
  console.log('->    are the public keys equal?', Boolean(bls.publicKeyIsEqual(pk1, pk2)))




  console.log('\nBeginning the share renewal round...')

  const newVvecs = [groupsVvec]

  console.log('-> member shares array reinitialized')
  members.forEach(member => {
    member.recievedShares.length = 0
    member.recievedShares.push(member.secretKeyShare)
  })

  console.log('-> running null-secret contribution generator')
  // the process is very similar, only `generateZeroContribution` works with a null secret
  members.forEach(id => {
    const {verificationVector, secretKeyContribution} = dkg.generateZeroContribution(bls, members.map(m => m.id), threshold)
    // the verification vector should be posted publically so that everyone
    // in the group can see it
    newVvecs.push(verificationVector)

    // Each secret key contribution is then encrypted and sent to the member it is for.
    secretKeyContribution.forEach((sk, i) => {
      // when a group member receives its share, it verifies it against the
      // verification vector of the sender and then saves it
      const member = members[i]
      const verified = dkg.verifyContributionShare(bls, member.id, sk, verificationVector)
      if (!verified) {
        throw new Error('invalid share!')
      }
      member.recievedShares.push(sk)
    })
  })

  // now each members adds together all received secret key contributions shares to get a
  // single secretkey share for the group used for signing message for the group
  members.forEach((member, i) => {
    const sk = dkg.addContributionShares(bls, member.recievedShares)
    member.secretKeyShare = sk
  })
  console.log('-> new secret shares have been generated')

  // Now any one can add together the all verification vectors posted by the
  // members of the group to get a single verification vector of for the group
  const newGroupsVvec = dkg.addVerificationVectors(bls, newVvecs)
  console.log('-> verification vector computed')

  // the groups verifcation vector contains the groups public key. The group's
  // public key is the first element in the array
  const newGroupsPublicKey = newGroupsVvec[0]

  verified = (bls.publicKeyIsEqual(newGroupsPublicKey, groupsPublicKey))
  console.log('-> public key should not have changed :', (verified ? 'success' : 'failure'))

  console.log('-> testing signature using new shares')
  // now we can select any 4 members to sign on a message
  sigs.length = 0
  signersIds.length = 0
  for (let i = 0; i < threshold; i++) {
    const sig = bls.signature()
    bls.sign(sig, members[i].secretKeyShare, message)
    sigs.push(sig)
    signersIds.push(members[i].id)
  }

  // then anyone can combine the signatures to get the groups signature
  // the resulting signature will also be the same no matter which members signed
  const groupsNewSig = bls.signature()
  bls.signatureRecover(groupsNewSig, sigs, signersIds)

  const newSigArray = bls.signatureExport(groupsNewSig)
  const newSigBuf = Buffer.from(newSigArray)
  console.log('->    sigtest result : ', newSigBuf.toString('hex'))
  console.log('->    signature comparison :', ((newSigBuf.equals(sigBuf)) ? 'success' : 'failure'))

  verified = bls.verify(groupsNewSig, groupsPublicKey, message)
  console.log('->    verified ?', Boolean(verified))

