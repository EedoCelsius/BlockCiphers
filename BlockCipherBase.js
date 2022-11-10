
module.exports = class BlockCipherBase {
    constructor() {
        this._blockBuffer = new ArrayBuffer(64)
        this._blockView = new DataView(this._blockBuffer)
        this._blockOffset = this._iterated = 0
        this._lastUpdate = -1
    }

    run(data, offset, end) {
        if (data instanceof ArrayBuffer) return this.arrayBuffer(data, offset, end)
        else if (data instanceof DataView) return this.dataView(data, offset, end)
        switch (data.BYTES_PER_ELEMENT) {
            case 1: return this.int8(data, offset, end)
            case 2: return this.int16(data, offset, end)
            default: return this.int32(data, offset, end)
        }
    }

    arrayBuffer(arrayBuffer, offset, end) {
        return this.dataView(new DataView(arrayBuffer), offset, end)
    }

    dataView(dataView, offset = 0, end = dataView.byteLength) {
        if (this._blockOffset === 64) this._iterated++, this._blockOffset = 0
        if (this._lastUpdate !== this._iterated) this._updateBlockBuffer()

        this._run_dataView_noUpdate(dataView, offset, offset += Math.min(64 - this._blockOffset, end - offset))

        if (offset >= end) {
            this._lastUpdate = this._iterated
            return dataView
        }
        this._iterated++, this._blockOffset = 0

        const lastIteration = Math.floor((end - offset) / 64) + this._iterated
        while (this._iterated < lastIteration) {
            this._updateBlockBuffer()
            for (let repeated = 0; repeated < 16; repeated++) {
                dataView.setUint32(offset, dataView.getUint32(offset) ^ this._blockView.getUint32(this._blockOffset))
                offset += 4, this._blockOffset += 4
            }
            this._iterated++, this._blockOffset = 0
        }

        if (offset >= end) {
            this._lastUpdate = this._iterated
            return dataView
        }
        this._updateBlockBuffer()

        this._run_dataView_noUpdate(dataView, offset, end)

        this._lastUpdate = this._iterated
        return dataView
    }

    _run_dataView_noUpdate(dataView, offset, end) {
        switch ((end - offset) % 4) {
            case 1:
                dataView.setUint8(offset, dataView.getUint8(offset) ^ this._blockView.getUint8(this._blockOffset))
                offset += 1, this._blockOffset += 1
                break
            case 2:
                dataView.setUint16(offset, dataView.getUint16(offset) ^ this._blockView.getUint16(this._blockOffset))
                offset += 2, this._blockOffset += 2
                break
            case 3:
                dataView.setUint8(offset, dataView.getUint8(offset) ^ this._blockView.getUint8(this._blockOffset))
                offset += 1, this._blockOffset += 1
                dataView.setUint16(offset, dataView.getUint16(offset) ^ this._blockView.getUint16(this._blockOffset))
                offset += 2, this._blockOffset += 2
                break
        }
        while (offset < end) {
            dataView.setUint32(offset, dataView.getUint32(offset) ^ this._blockView.getUint32(this._blockOffset))
            offset += 4, this._blockOffset += 4
        }
    }

    int8(int8Arr, offset = 0, end = int8Arr.length) {
        if (this._blockOffset === 64) this._iterated++, this._blockOffset = 0
        if (this._lastUpdate !== this._iterated) this._updateBlockBuffer()

        this._run_int8(int8Arr, offset, offset += Math.min((4 - ((int8Arr.byteOffset + offset) % 4)) % 4, end - offset))

        const Uint32Length = Math.floor((end - offset) / 4)
        if (Uint32Length) {
            this.int32(new Uint32Array(int8Arr.buffer, int8Arr.byteOffset + offset, Uint32Length))
            offset += Uint32Length * 4
        }

        this._run_int8(int8Arr, offset, end)

        this._lastUpdate = this._iterated
        return int8Arr
    }

    _run_int8(int8Arr, offset, end) {
        while (offset < end) {
            if (this._blockOffset === 64) {
                this._iterated++, this._blockOffset = 0
                this._updateBlockBuffer()
            }
            int8Arr[offset++] ^= this._blockView.getUint8(this._blockOffset)
            this._blockOffset += 1
        }
    }

    int16(int16Arr, offset = 0, end = int16Arr.length) {
        if (this._blockOffset === 64) this._iterated++, this._blockOffset = 0
        if (this._lastUpdate !== this._iterated) this._updateBlockBuffer()

        if ((int16Arr.byteOffset + offset * 2) % 4) this._run_int16(int16Arr, offset, ++offset)

        const Uint32Length = Math.floor((end - offset) / 2)
        if (Uint32Length) {
            this.int32(new Uint32Array(int16Arr.buffer, int16Arr.byteOffset + offset * 2, Uint32Length))
            offset += Uint32Length * 2
        }

        this._run_int16(int16Arr, offset, end)

        this._lastUpdate = this._iterated
        return int16Arr
    }

    _run_int16(int16Arr, offset, end) {
        while (offset < end) {
            if (this._blockOffset === 63) {
                int16Arr[offset] ^= this._blockView.getUint8(63, true)
                this._iterated++
                this._updateBlockBuffer()
                int16Arr[offset++] ^= this._blockView.getUint8(0, true) << 8
                this._blockOffset = 1
            }
            else {
                if (this._blockOffset === 64) {
                    this._iterated++, this._blockOffset = 0
                    this._updateBlockBuffer()
                }
                int16Arr[offset++] ^= this._blockView.getUint16(this._blockOffset, true)
                this._blockOffset += 2
            }
        }
    }

    int32(int32Arr, offset = 0, end = int32Arr.length) {
        if (this._blockOffset === 64) this._iterated++, this._blockOffset = 0
        if (this._lastUpdate !== this._iterated) this._updateBlockBuffer()
        let offsetint = 0

        if (offset < end && this._blockOffset % 4) {
            int32Arr[offset] ^= this._blockView.getUint32(Math.floor(this._blockOffset / 4) * 4, true) >>> (offsetint = (this._blockOffset % 4) * 8)
            this._blockOffset = Math.ceil(this._blockOffset / 4) * 4
        }

        const lastBlock = Math.min(this._blockOffset + 4 * (end - offset), 64)
        while (this._blockOffset < lastBlock) {
            int32Arr[offset++] ^= this._blockView.getUint32(this._blockOffset, true) << (32 - offsetint)
            if (offsetint) int32Arr[offset] ^= this._blockView.getUint32(this._blockOffset, true) >>> offsetint
            this._blockOffset += 4
        }

        for (let repeated = 0, repeat = Math.floor((end - offset) / 16); repeated < repeat; repeated++) {
            this._iterated++, this._blockOffset = 0
            this._updateBlockBuffer()
            while (this._blockOffset < 64) {
                int32Arr[offset++] ^= this._blockView.getUint32(this._blockOffset, true) << (32 - offsetint)
                if (offsetint) int32Arr[offset] ^= this._blockView.getUint32(this._blockOffset, true) >>> offsetint
                this._blockOffset += 4
            }
        }

        if (offset < end) {
            this._iterated++, this._blockOffset = 0
            this._updateBlockBuffer()
            while (offset < end) {
                int32Arr[offset++] ^= this._blockView.getUint32(this._blockOffset, true) << (32 - offsetint)
                if (offsetint) int32Arr[offset] ^= this._blockView.getUint32(this._blockOffset, true) >>> offsetint
                this._blockOffset += 4
            }
        }

        if (offsetint) this._blockOffset -= 4 - offsetint / 8

        this._lastUpdate = this._iterated
        return int32Arr
    }

    reset() {
        this._blockOffset = this._iterated = 0
        this._lastUpdate = -1
    }

    get encryptedBytes() {
        return this._iterated * 64 + this._blockOffset
    }
    set encryptedBytes(n) {
        this._iterated = Math.floor(n / 64)
        this._blockOffset = n % 64
    }
}
