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
        member.initId(myId)

        memberIds.forEach((id) => {
          if (id !== myId) {
            member.addMember(id)
          }
        })

        contributions[myId] = member.generateContribution()
        members[myId] = member
      })
      assert.true(Object.keys(contributions).length === memberIds.length, 'Correct number of contributions')

      // recieve contribution round
      memberIds.forEach((myId) => {
        assert.true(contributions[myId].vvec.length === threshold, 'verification vector has length = treshold')
        memberIds.forEach((id) => {
          if (id !== myId) {
            // assert.ok(contributions[id].contrib[myId], `Contribution from peer ${memberIds.indexOf(id)} to peer ${memberIds.indexOf(myId)} exists`)
            members[myId].storeVerificationVector(id, contributions[id].vvec)
            assert.true(members[myId].recieveContribution(id, contributions[id].contrib[myId]), 'contribution valid')
          }
        })
      })

      // check that everything worked
      var groupKeys = []
      memberIds.forEach((id) => {
        if (members[id].groupPublicKeyExport) groupKeys.push(members[id].groupPublicKeyExport)
      })
      assert.true(groupKeys.length === memberIds.length, 'Every member has a group public key')
      const groupKeyStrings = groupKeys.map(key => Buffer.from(key).toString('hex'))
      assert.true(groupKeyStrings.every(key => key === groupKeyStrings[0]), 'Group public keys are all identical')

      // sign a message
      const message = 'its nice to be important but its more important to be nice'
      const signatures = {}
      // 3 members sign
      memberIds.slice(0, threshold).forEach((myId) => {
        signatures[myId] = members[myId].sign(message)
        assert.ok(signatures[myId].signature, 'Signature OK')
      })
      memberIds.slice(0, threshold).forEach((myId) => {
        memberIds.slice(0, threshold).forEach((id) => {
          if (id !== myId) {
            members[myId].recieveSignature(signatures[id].signature, id, signatures[id].hashOfMessage)
          }
        })
      })

      const hashOfMessage = signatures[memberIds[0]].hashOfMessage
      assert.ok(members[memberIds[1]].groupSignatures[hashOfMessage], 'Group signature valid')
      next()
    })
  })
})
