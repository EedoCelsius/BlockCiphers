
module.exports = class SalsaCipher extends require("./BlockCipherBase") {
    constructor(key, nonce, rounds) {
        super()
        this._blockUint32 = new Uint32Array(this._blockBuffer)
        this._state = new Uint32Array([1634760805, 0, 0, 0, 0, 857760878, 0, 0, 0, 0, 2036477234, 0, 0, 0, 0, 1797285236])
        this.reset(key || [], nonce || [], rounds || 20)
    }

    reset(key, nonce, rounds) {
        super.reset()
        if (key) {
            if (key.length !== 8) throw Error("Length of 'key' argument should be 8")
            this._state[1] = key[0], this._state[2] = key[1], this._state[3] = key[2], this._state[4] = key[3],
                this._state[11] = key[4], this._state[12] = key[5], this._state[13] = key[6], this._state[14] = key[7]
        }
        if (nonce) {
            if (nonce.length !== 2) throw Error("Length of 'nonce' argument should be 2")
            this._state[6] = nonce[0], this._state[7] = nonce[1]
        }
        if (rounds) {
            if (rounds % 2 !== 0) throw Error("Value of 'rounds' argument should be an even number")
            this._rounds = rounds
        }
    }

    _updateBlockBuffer() {
        this._state[8] = this._iterated, this._state[9] = Math.floor(this._iterated / 0x100000000)
        for (let i = 0; i < 16; i++) this._blockUint32[i] = this._state[i]

        for (let r = 0; r < this._rounds; r += 2) {
            this._blockUint32[4] ^= ROTL(this._blockUint32[0] + this._blockUint32[12], 7)
            this._blockUint32[8] ^= ROTL(this._blockUint32[4] + this._blockUint32[0], 9)
            this._blockUint32[12] ^= ROTL(this._blockUint32[8] + this._blockUint32[4], 13)
            this._blockUint32[0] ^= ROTL(this._blockUint32[12] + this._blockUint32[8], 18)
            this._blockUint32[9] ^= ROTL(this._blockUint32[5] + this._blockUint32[1], 7)
            this._blockUint32[13] ^= ROTL(this._blockUint32[9] + this._blockUint32[5], 9)
            this._blockUint32[1] ^= ROTL(this._blockUint32[13] + this._blockUint32[9], 13)
            this._blockUint32[5] ^= ROTL(this._blockUint32[1] + this._blockUint32[13], 18)
            this._blockUint32[14] ^= ROTL(this._blockUint32[10] + this._blockUint32[6], 7)
            this._blockUint32[2] ^= ROTL(this._blockUint32[14] + this._blockUint32[10], 9)
            this._blockUint32[6] ^= ROTL(this._blockUint32[2] + this._blockUint32[14], 13)
            this._blockUint32[10] ^= ROTL(this._blockUint32[6] + this._blockUint32[2], 18)
            this._blockUint32[3] ^= ROTL(this._blockUint32[15] + this._blockUint32[11], 7)
            this._blockUint32[7] ^= ROTL(this._blockUint32[3] + this._blockUint32[15], 9)
            this._blockUint32[11] ^= ROTL(this._blockUint32[7] + this._blockUint32[3], 13)
            this._blockUint32[15] ^= ROTL(this._blockUint32[11] + this._blockUint32[7], 18)
            this._blockUint32[1] ^= ROTL(this._blockUint32[0] + this._blockUint32[3], 7)
            this._blockUint32[2] ^= ROTL(this._blockUint32[1] + this._blockUint32[0], 9)
            this._blockUint32[3] ^= ROTL(this._blockUint32[2] + this._blockUint32[1], 13)
            this._blockUint32[0] ^= ROTL(this._blockUint32[3] + this._blockUint32[2], 18)
            this._blockUint32[6] ^= ROTL(this._blockUint32[5] + this._blockUint32[4], 7)
            this._blockUint32[7] ^= ROTL(this._blockUint32[6] + this._blockUint32[5], 9)
            this._blockUint32[4] ^= ROTL(this._blockUint32[7] + this._blockUint32[6], 13)
            this._blockUint32[5] ^= ROTL(this._blockUint32[4] + this._blockUint32[7], 18)
            this._blockUint32[11] ^= ROTL(this._blockUint32[10] + this._blockUint32[9], 7)
            this._blockUint32[8] ^= ROTL(this._blockUint32[11] + this._blockUint32[10], 9)
            this._blockUint32[9] ^= ROTL(this._blockUint32[8] + this._blockUint32[11], 13)
            this._blockUint32[10] ^= ROTL(this._blockUint32[9] + this._blockUint32[8], 18)
            this._blockUint32[12] ^= ROTL(this._blockUint32[15] + this._blockUint32[14], 7)
            this._blockUint32[13] ^= ROTL(this._blockUint32[12] + this._blockUint32[15], 9)
            this._blockUint32[14] ^= ROTL(this._blockUint32[13] + this._blockUint32[12], 13)
            this._blockUint32[15] ^= ROTL(this._blockUint32[14] + this._blockUint32[13], 18)
        }

        for (let i = 0; i < 16; i++) this._blockUint32[i] += this._state[i]
    }
}

function ROTL(data, shift) {
    return (data << shift) | (data >>> (32 - shift))
}
