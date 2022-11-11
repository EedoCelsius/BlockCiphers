
module.exports = class ChachaCipher extends require("./BlockCipherBase") {
    constructor(key, nonce, rounds) {
        super()
        this._blockUint32 = new Uint32Array(this._blockBuffer)
        this._state = new Uint32Array([1634760805, 857760878, 2036477234, 1797285236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        this.reset(key || [], nonce || [0, 0], rounds || 20)
    }

    reset(key, nonce, rounds) {
        super.reset()
        if (key) {
            if (ArrayBuffer.isView(key)) {
                if (key.byteLength !== 32) throw Error("Byte length of 'key' argument should be 32")
                if (!(key instanceof Uint32Array)) key = new Uint32Array(key.slice().buffer)
            }
            else if (key.length !== 8) throw Error("Length of 'key' argument should be 8")
            
            this._state[4] = key[0], this._state[5] = key[1], this._state[6] = key[2], this._state[7] = key[3],
                this._state[8] = key[4], this._state[9] = key[5], this._state[10] = key[6], this._state[11] = key[7]
        }
        if (nonce) {
            if (ArrayBuffer.isView(nonce)) {
                if (nonce.byteLength !== 32) throw Error("Byte length of 'nonce' argument should be 32")
                if (!(nonce instanceof Uint32Array)) nonce = new Uint32Array(nonce.slice().buffer)
            }
            else if (nonce.length !== 8) throw Error("Length of 'nonce' argument should be 2")
            
            this._base[14] = nonce[0], this._base[15] = nonce[1]
        }
        if (rounds) {
            this._rounds = rounds
        }
    }

    _updateBlockBuffer() {
        this._state[12] = this._iterated, this._state[13] = Math.floor(this._iterated / 0x100000000)
        this._blockUint32.set(this._state)

        for (let round = 0; round < this._rounds; round++) {
            this._blockUint32[12] = ROTL(this._blockUint32[12] ^ (this._blockUint32[0] += this._blockUint32[4]), 16)
            this._blockUint32[4] = ROTL(this._blockUint32[4] ^ (this._blockUint32[8] += this._blockUint32[12]), 12)
            this._blockUint32[12] = ROTL(this._blockUint32[12] ^ (this._blockUint32[0] += this._blockUint32[4]), 8)
            this._blockUint32[4] = ROTL(this._blockUint32[4] ^ (this._blockUint32[8] += this._blockUint32[12]), 7)
            this._blockUint32[13] = ROTL(this._blockUint32[13] ^ (this._blockUint32[1] += this._blockUint32[5]), 16)
            this._blockUint32[5] = ROTL(this._blockUint32[5] ^ (this._blockUint32[9] += this._blockUint32[13]), 12)
            this._blockUint32[13] = ROTL(this._blockUint32[13] ^ (this._blockUint32[1] += this._blockUint32[5]), 8)
            this._blockUint32[5] = ROTL(this._blockUint32[5] ^ (this._blockUint32[9] += this._blockUint32[13]), 7)
            this._blockUint32[14] = ROTL(this._blockUint32[14] ^ (this._blockUint32[2] += this._blockUint32[6]), 16)
            this._blockUint32[6] = ROTL(this._blockUint32[6] ^ (this._blockUint32[10] += this._blockUint32[14]), 12)
            this._blockUint32[14] = ROTL(this._blockUint32[14] ^ (this._blockUint32[2] += this._blockUint32[6]), 8)
            this._blockUint32[6] = ROTL(this._blockUint32[6] ^ (this._blockUint32[10] += this._blockUint32[14]), 7)
            this._blockUint32[15] = ROTL(this._blockUint32[15] ^ (this._blockUint32[3] += this._blockUint32[7]), 16)
            this._blockUint32[7] = ROTL(this._blockUint32[7] ^ (this._blockUint32[11] += this._blockUint32[15]), 12)
            this._blockUint32[15] = ROTL(this._blockUint32[15] ^ (this._blockUint32[3] += this._blockUint32[7]), 8)
            this._blockUint32[7] = ROTL(this._blockUint32[7] ^ (this._blockUint32[11] += this._blockUint32[15]), 7)
            
            if (round++ < this._rounds) break
            
            this._blockUint32[15] = ROTL(this._blockUint32[15] ^ (this._blockUint32[0] += this._blockUint32[5]), 16)
            this._blockUint32[5] = ROTL(this._blockUint32[5] ^ (this._blockUint32[10] += this._blockUint32[15]), 12)
            this._blockUint32[15] = ROTL(this._blockUint32[15] ^ (this._blockUint32[0] += this._blockUint32[5]), 8)
            this._blockUint32[5] = ROTL(this._blockUint32[5] ^ (this._blockUint32[10] += this._blockUint32[15]), 7)
            this._blockUint32[12] = ROTL(this._blockUint32[12] ^ (this._blockUint32[1] += this._blockUint32[6]), 16)
            this._blockUint32[6] = ROTL(this._blockUint32[6] ^ (this._blockUint32[11] += this._blockUint32[12]), 12)
            this._blockUint32[12] = ROTL(this._blockUint32[12] ^ (this._blockUint32[1] += this._blockUint32[6]), 8)
            this._blockUint32[6] = ROTL(this._blockUint32[6] ^ (this._blockUint32[11] += this._blockUint32[12]), 7)
            this._blockUint32[13] = ROTL(this._blockUint32[13] ^ (this._blockUint32[2] += this._blockUint32[7]), 16)
            this._blockUint32[7] = ROTL(this._blockUint32[7] ^ (this._blockUint32[8] += this._blockUint32[13]), 12)
            this._blockUint32[13] = ROTL(this._blockUint32[13] ^ (this._blockUint32[2] += this._blockUint32[7]), 8)
            this._blockUint32[7] = ROTL(this._blockUint32[7] ^ (this._blockUint32[8] += this._blockUint32[13]), 7)
            this._blockUint32[14] = ROTL(this._blockUint32[14] ^ (this._blockUint32[3] += this._blockUint32[4]), 16)
            this._blockUint32[4] = ROTL(this._blockUint32[4] ^ (this._blockUint32[9] += this._blockUint32[14]), 12)
            this._blockUint32[14] = ROTL(this._blockUint32[14] ^ (this._blockUint32[3] += this._blockUint32[4]), 8)
            this._blockUint32[4] = ROTL(this._blockUint32[4] ^ (this._blockUint32[9] += this._blockUint32[14]), 7)
        }

        for (let i = 0; i < 16; i++) this._blockUint32[i] += this._state[i]
    }
}

function ROTL(data, shift) {
    return (data << shift) | (data >>> (32 - shift))
}
