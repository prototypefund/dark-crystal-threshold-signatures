const { describe } = require('tape-plus')
const Member = require('..')

describe('basic', (context) => {
  context('', (assert, next) => {
    var members = {}
    var vvecs = {}
    const memberIds = [10314, 30911, 25411, 8608, 31524]

    Member.blsInit(() => {
      memberIds.forEach((myId) => {
        var member = Member(3, 5) // 3 of 5

        member.initId(myId)
        memberIds.forEach((id) => {
          if (id !== myId) {
            member.addMember(id)
          }
        })
        vvecs[myId] = member.generateContribution()
        members[myId] = member
      })

      // recieve contribution round
      memberIds.forEach((myId) => {
        memberIds.forEach((id) => {
          if (id !== myId) {
            members[myId].storeVerificationVector(vvecs[id])
            members[myId].recieveContribution(id, members[id].members[myId].contrib)
          }
        })
      })

      // sign a message
      const message = 'its nice to be important but its more important to be nice'
      const signatures = {}
      memberIds.forEach((myId) => {
        signatures[myId] = members[myId].sign(message)
      })
      memberIds.forEach((myId) => {
        memberIds.forEach((id) => {
          if (id !== myId) {
            members[myId].recieveSignature(signatures[id].signature, id, signatures[id].hashOfMessage)
          }
        })
      })
      const hashOfMessage = signatures[memberIds[0]].hashOfMessage
      assert.ok(members[memberIds[1]].groupSignatures[hashOfMessage], 'group signature built')
      next()
    })
  })
})
