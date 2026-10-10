// Package kiwi implements the KiwiSDR client protocol as understood from
// reading the kiwiclient reference (jks-prv/kiwiclient) and the server
// source (jks-prv/KiwiSDR, rx/rx_sound.cpp and rx/rx_cmd.cpp). No code is
// ported: kiwiclient's core module carries no license grant.
//
// Wire format summary (all learned, then verified against live receivers):
//
//	Every WebSocket message starts with a 3-byte tag: "MSG", "SND", "W/F", "EXT".
//
//	MSG: tag, one space, then space-separated "name=value" or bare "name"
//	     tokens. Values may be URL-encoded (server uses %XX for some).
//
//	SND: tag, then
//	     flags   u8
//	     seq     u32 little-endian
//	     smeter  u16 big-endian   rssi_dBm = smeter/10 - 127
//	     [stereo only: last_gps_solution u8, dummy u8, gpssec u32 LE, gpsnsec u32 LE]
//	     audio   if flags&COMPRESSED: IMA ADPCM, 2 samples per byte, low nibble first
//	             else: int16 samples, big-endian unless flags&LITTLE_ENDIAN
package kiwi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// SND flag bits (rx/rx_sound.cpp).
const (
	FlagLPF          = 0x01
	FlagADCOverflow  = 0x02
	FlagNewFreq      = 0x04
	FlagStereo       = 0x08
	FlagCompressed   = 0x10
	FlagRestart      = 0x20
	FlagSquelchUI    = 0x40
	FlagLittleEndian = 0x80
)

const sndHeaderLen = 1 + 4 + 2
const sndStereoExtraLen = 1 + 1 + 4 + 4

// MaxSNDPayload bounds the audio bytes we will accept from one SND frame.
// A normal frame carries ~2 KiB (ADPCM) or ~4 KiB (PCM); 64 KiB leaves
// margin for wideband modes while still refusing absurd frames.
const MaxSNDPayload = 64 << 10

// SNDFrame is a parsed audio frame.
type SNDFrame struct {
	Flags  byte
	Seq    uint32
	SMeter uint16
	// Audio is the raw audio payload (still encoded). It aliases the
	// input message buffer.
	Audio []byte
}

// RSSI returns the S-meter reading in dBm.
func (f *SNDFrame) RSSI() float64 { return float64(f.SMeter)/10 - 127 }

// Compressed reports whether Audio is IMA ADPCM.
func (f *SNDFrame) Compressed() bool { return f.Flags&FlagCompressed != 0 }

// ParseSND parses the body of a "SND" message (bytes after the 3-byte tag).
func ParseSND(body []byte) (SNDFrame, error) {
	var f SNDFrame
	if len(body) < sndHeaderLen {
		return f, fmt.Errorf("SND frame too short: %d bytes", len(body))
	}
	f.Flags = body[0]
	f.Seq = binary.LittleEndian.Uint32(body[1:5])
	f.SMeter = binary.BigEndian.Uint16(body[5:7])
	rest := body[sndHeaderLen:]
	if f.Flags&FlagStereo != 0 {
		if len(rest) < sndStereoExtraLen {
			return f, errors.New("SND stereo frame missing GPS header")
		}
		rest = rest[sndStereoExtraLen:]
	}
	if len(rest) > MaxSNDPayload {
		return f, fmt.Errorf("SND payload %d bytes exceeds limit", len(rest))
	}
	if f.Flags&FlagCompressed == 0 && len(rest)%2 != 0 {
		return f, errors.New("SND PCM payload has odd length")
	}
	f.Audio = rest
	return f, nil
}

// DecodeAudio appends the decoded mono int16 samples to dst. dec is used
// only for compressed frames. Stereo (IQ) frames are not expected in
// Kiwi Garden; they are decoded as interleaved samples and left to the
// caller to interpret.
func DecodeAudio(dst []int16, f *SNDFrame, dec *ADPCM) []int16 {
	if f.Compressed() {
		return dec.Decode(dst, f.Audio)
	}
	a := f.Audio
	le := f.Flags&FlagLittleEndian != 0
	for i := 0; i+1 < len(a); i += 2 {
		var v uint16
		if le {
			v = binary.LittleEndian.Uint16(a[i:])
		} else {
			v = binary.BigEndian.Uint16(a[i:])
		}
		dst = append(dst, int16(v))
	}
	return dst
}

// MsgParam is one "name=value" (or bare "name") token from a MSG.
type MsgParam struct {
	Name  string
	Value string
	HasEq bool
}

// MaxMSGTokens bounds the number of tokens parsed from one MSG.
const MaxMSGTokens = 64

// ParseMSG splits the body of a "MSG" message (bytes after the tag, which
// begin with a single space). Values are returned raw (not URL-decoded);
// use Unescape for fields the server encodes.
func ParseMSG(body []byte) ([]MsgParam, error) {
	s := strings.TrimPrefix(string(body), " ")
	if s == "" {
		return nil, nil
	}
	var out []MsgParam
	for tok := range strings.SplitSeq(s, " ") {
		if tok == "" {
			continue
		}
		if len(out) >= MaxMSGTokens {
			return out, errors.New("MSG has too many tokens")
		}
		name, val, ok := strings.Cut(tok, "=")
		out = append(out, MsgParam{Name: name, Value: val, HasEq: ok})
	}
	return out, nil
}

// Unescape URL-decodes a MSG value, returning the input unchanged on error.
func Unescape(v string) string {
	u, err := url.QueryUnescape(v)
	if err != nil {
		return v
	}
	return u
}

// ExpectedSampleRates are the nominal audio rates a KiwiSDR can run at.
var ExpectedSampleRates = []float64{12000, 20250}

// SampleRateOK reports whether a reported rate is within 1 percent of a
// known nominal rate. Anything else is a broken or hostile receiver.
func SampleRateOK(sr float64) bool {
	for _, e := range ExpectedSampleRates {
		if sr > 0 && sr/e > 0.99 && sr/e < 1.01 {
			return true
		}
	}
	return false
}

// SplitTag separates the 3-byte tag from the rest of a message.
func SplitTag(msg []byte) (tag string, body []byte, ok bool) {
	if len(msg) < 3 {
		return "", nil, false
	}
	return string(msg[:3]), msg[3:], true
}
