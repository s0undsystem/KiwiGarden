package kiwi

// IMA ADPCM (DVI4) decoder, implemented from the IMA specification.
// KiwiSDR packs two 4-bit codes per byte, low nibble first.
//
// The step table and index adjustments are the standard IMA constants.
// All state is clamped on every sample, so no input byte sequence can
// drive the index out of the table or the predictor outside int16.

var imaStepTable = [89]int32{
	7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34,
	37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143,
	157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494,
	544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552,
	1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026,
	4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442,
	11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623,
	27086, 29794, 32767,
}

var imaIndexAdjust = [16]int32{-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8}

// ADPCM holds decoder state across frames. The zero value is the reset state.
type ADPCM struct {
	index int32
	prev  int32
}

// Reset returns the decoder to its initial state. KiwiSDR resets the
// encoder when the channel is (re)started or the mode changes.
func (d *ADPCM) Reset() { d.index, d.prev = 0, 0 }

// Preset sets the decoder state. Used when joining a stream mid-way
// (the server sends "audio_adpcm_state=index,prev"). Values are clamped.
func (d *ADPCM) Preset(index, prev int32) {
	d.index = clamp32(index, 0, int32(len(imaStepTable)-1))
	d.prev = clamp32(prev, -32768, 32767)
}

func (d *ADPCM) sample(code byte) int16 {
	code &= 0x0F
	step := imaStepTable[d.index]
	d.index = clamp32(d.index+imaIndexAdjust[code], 0, int32(len(imaStepTable)-1))
	diff := step >> 3
	if code&1 != 0 {
		diff += step >> 2
	}
	if code&2 != 0 {
		diff += step >> 1
	}
	if code&4 != 0 {
		diff += step
	}
	if code&8 != 0 {
		diff = -diff
	}
	d.prev = clamp32(d.prev+diff, -32768, 32767)
	return int16(d.prev)
}

// Decode appends 2*len(in) samples to dst and returns the extended slice.
func (d *ADPCM) Decode(dst []int16, in []byte) []int16 {
	for _, b := range in {
		dst = append(dst, d.sample(b&0x0F), d.sample(b>>4))
	}
	return dst
}

func clamp32(v, lo, hi int32) int32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
