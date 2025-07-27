import {assert} from 'chai'
import {PrivateKey, UInt64} from '@wharfkit/antelope'
import {sealMessage, unsealMessage} from '../../src/index'

suite('utils', function () {
    test('sealMessage', async function () {
        const from = PrivateKey.generate('K1')
        const to = PrivateKey.generate('K1').toPublic()
        const nonce = UInt64.from(1234567890)
        const message = 'Hello, World!'

        const sealedMessage = await sealMessage(message, from, to, nonce)
        assert.notEqual(sealedMessage.toString('hex'), message)
        assert.isTrue(sealedMessage.length > 0)
        assert.match(sealedMessage.toString('hex'), /^[0-9a-f]+$/)
        assert.equal(sealedMessage.length % 16, 0)
    })

    test('unsealMessage', async function () {
        const from = PrivateKey.generate('K1')
        const to = PrivateKey.generate('K1')
        const nonce = UInt64.from(1234567890)
        const message = 'Hello, World!'

        const sealedMessage = await sealMessage(message, from, to.toPublic(), nonce)
        const unsealedMessage = await unsealMessage(sealedMessage, to, from.toPublic(), nonce)
        assert.equal(unsealedMessage, message)
    })
})
