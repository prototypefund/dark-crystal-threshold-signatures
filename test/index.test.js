const { describe } = require('tape-plus')
const Member = require('..')
const async = require('async')

describe('basic', (context) => {
  context('', (assert, next) => {
    var members = {}
    var vvecs = {}
    const memberIds = [10314, 30911, 25411, 8608, 31524]
    async.each(memberIds, (myId, callback) => {
      var member = Member(3, 5) // 3 of 5
      member.ready(() => {
        member.initId(myId)
        memberIds.forEach((id) => {
          if (id !== myId) {
            member.addMember(id)
          }
        })
        vvecs[myId] = member.generateContribution()
        members[myId] = member
        callback()
      })
    }, recieveContributionRound)

    function recieveContributionRound () {
      members.forEach((member) => {
        memberIds.forEach((id) => {
          if (id !== member.id) {
            member.StoreVerificationVector(vvecs[id])
            member.recieveContribution(id, members[id].members[member.id].contrib)
          }
        })
      })

      signMessage()
    }

    function signMessage () {
      const message = 'its nice to be important but its more important to be nice'
      const signatures = {}
      members.forEach((member) => {
        signatures[member.id] = member.sign(message)
      })
      members.forEach((member) => {
        memberIds.forEach((id) => {
          if (id !== member.id) {
            member.recieveSignature(signatures[id].signature, id, signatures[id].hashOfMessage)
          }
        })
      })
      assert(members[1].groupSignatures[signatures[members[1].id].hashOfMessage])
    }
  })
})
