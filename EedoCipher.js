
module.exports = class EedoCipher extends require("./BlockCipherBase") {
    constructor(key, nonce) {
        super()
        this._blockUint32 = new Uint32Array(this._blockBuffer)
        this.reset(key || [], nonce || [])
    }

    reset(key, nonce) {
        super.reset()
        if (key) {
            if (ArrayBuffer.isView(key)) {
                if (key.byteLength !== 32) throw Error("Byte length of 'key' argument should be 32")
                if (key instanceof Uint32Array) this._key = key.slice()
                else this._key = new Uint32Array(key.slice().buffer)
            }
            else {
                if (key.length !== 8) throw Error("Length of 'key' argument should be 8")
                this._key = new Uint32Array(key)
            }
        }
        if (nonce) {
            if (ArrayBuffer.isView(nonce)) {
                if (nonce.byteLength !== 8) throw Error("Byte length of 'nonce' argument should be 8")
                if (nonce instanceof Uint32Array) this._nonce = nonce.slice()
                else this._nonce = new Uint32Array(nonce.slice().buffer)
            }
            else {
                if (nonce.length !== 2) throw Error("Length of 'nonce' argument should be 2")
                this._nonce = new Uint32Array(nonce)
            }
        }
    }

    _updateBlockBuffer() {
        const iterated0 = this._iterated % 0x100000000, iterated32 = Math.floor(this._iterated / 0x100000000)
        this._blockUint32[0] = 1868850501 + iterated0
        this._blockUint32[1] = this._key[0]
        this._blockUint32[2] = this._key[1]
        this._blockUint32[3] = this._key[2] + iterated32
        this._blockUint32[4] = this._key[3]
        this._blockUint32[5] = 1752197443 - iterated32
        this._blockUint32[6] = iterated0
        this._blockUint32[7] = this._nonce[0]
        this._blockUint32[8] = this._nonce[1]
        this._blockUint32[9] = -iterated0
        this._blockUint32[10] = 1934193253 + iterated32
        this._blockUint32[11] = this._key[4]
        this._blockUint32[12] = this._key[5] - iterated32
        this._blockUint32[13] = this._key[6]
        this._blockUint32[14] = this._key[7]
        this._blockUint32[15] = 1953718598 - iterated0

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
}

function ROTL(data, shift) {
    return (data << shift) | (data >>> (32 - shift))
}