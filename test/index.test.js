const { describe } = require('tape-plus')
const ThresholdSig = require('..')

const threshold = 3

describe('basic', (context) => {
  context('Group signatures', (assert, next) => {
    var members = {}
    var contributions = {}
    const memberIds = [10314, 30911, 25411, 8608, 31524]

    ThresholdSig.blsInit(() => {
      memberIds.forEach((myId) => {
        var member = ThresholdSig(threshold, memberIds.length) // 3 of 5
        const mySk = member.initId(myId)

        members[mySk] = member
      })
      Object.keys(members).forEach((mySk) => {
        Object.keys(members).forEach((sk) => {
          if (sk !== mySk) {
            members[mySk].addMember(sk)
          }
        })
        contributions[mySk] = members[mySk].generateContribution()
      })

      assert.true(Object.keys(contributions).length === memberIds.length, 'Correct number of contributions')

      // recieve contribution round
      Object.keys(members).forEach((myId) => {
        assert.true(contributions[myId].vvec.length === threshold, 'verification vector has length = treshold')
        Object.keys(members).forEach((id) => {
          if (id !== myId) {
            // assert.ok(contributions[id].contrib[myId], `Contribution from peer ${memberIds.indexOf(id)} to peer ${memberIds.indexOf(myId)} exists`)
            members[myId].storeVerificationVector(id, contributions[id].vvec)
            assert.true(members[myId].recieveContribution(id, contributions[id].contrib[myId]), 'contribution valid')
          }
        })
      })

      // check that everything worked
      var groupKeys = []
      Object.keys(members).forEach((id) => {
        if (members[id].groupPublicKeyExport) groupKeys.push(members[id].groupPublicKeyExport)
      })
      assert.true(groupKeys.length === memberIds.length, 'Every member has a group public key')
      const groupKeyStrings = groupKeys.map(key => Buffer.from(key).toString('hex'))
      assert.true(groupKeyStrings.every(key => key === groupKeyStrings[0]), 'Group public keys are all identical')

      // sign a message
      const message = 'its nice to be important but its more important to be nice'
      const signatures = {}
      // 3 members sign
      Object.keys(members).slice(0, threshold).forEach((myId) => {
        signatures[myId] = members[myId].sign(message)
        assert.ok(signatures[myId].signature, 'Signature OK')
      })
      Object.keys(members).slice(0, threshold).forEach((myId) => {
        Object.keys(members).slice(0, threshold).forEach((id) => {
          if (id !== myId) {
            members[myId].recieveSignature(signatures[id].signature, id, message)
          }
        })
      })
      // const hashOfMessage = signatures[Object.keys(signatures)[0]].hashOfMessage
      assert.ok(members[Object.keys(members)[1]].groupSignatures[message], 'Group signature valid')
      next()
    })
  })
})
