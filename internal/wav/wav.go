// Package wav writes 16-bit PCM mono WAV files.
package wav

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Write emits a canonical 44-byte RIFF/WAVE header followed by the samples.
func Write(w io.Writer, sampleRate int, samples []int16) error {
	if sampleRate <= 0 || sampleRate > 1<<20 {
		return fmt.Errorf("wav: bad sample rate %d", sampleRate)
	}
	dataLen := uint32(len(samples) * 2)
	var hdr [44]byte
	copy(hdr[0:], "RIFF")
	binary.LittleEndian.PutUint32(hdr[4:], 36+dataLen)
	copy(hdr[8:], "WAVE")
	copy(hdr[12:], "fmt ")
	binary.LittleEndian.PutUint32(hdr[16:], 16)
	binary.LittleEndian.PutUint16(hdr[20:], 1) // PCM
	binary.LittleEndian.PutUint16(hdr[22:], 1) // mono
	binary.LittleEndian.PutUint32(hdr[24:], uint32(sampleRate))
	binary.LittleEndian.PutUint32(hdr[28:], uint32(sampleRate)*2)
	binary.LittleEndian.PutUint16(hdr[32:], 2)
	binary.LittleEndian.PutUint16(hdr[34:], 16)
	copy(hdr[36:], "data")
	binary.LittleEndian.PutUint32(hdr[40:], dataLen)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	buf := make([]byte, 0, 8192)
	for i, s := range samples {
		buf = binary.LittleEndian.AppendUint16(buf, uint16(s))
		if len(buf) == cap(buf) || i == len(samples)-1 {
			if _, err := w.Write(buf); err != nil {
				return err
			}
			buf = buf[:0]
		}
	}
	return nil
}
