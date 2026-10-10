package kiwi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestADPCMClamps(t *testing.T) {
	var d ADPCM
	// All "increase step" codes repeatedly: index must saturate at 88 and
	// the predictor at int16 bounds, never panic.
	in := bytes.Repeat([]byte{0x77}, 10000)
	out := d.Decode(nil, in)
	if len(out) != 20000 {
		t.Fatalf("len %d", len(out))
	}
	if d.index != 88 {
		t.Fatalf("index %d", d.index)
	}
	if out[len(out)-1] != 32767 {
		t.Fatalf("predictor did not saturate: %d", out[len(out)-1])
	}
	in = bytes.Repeat([]byte{0xFF}, 10000)
	out = d.Decode(nil, in)
	if out[len(out)-1] != -32768 {
		t.Fatalf("negative saturation: %d", out[len(out)-1])
	}
	d.Preset(1000, 1<<20)
	if d.index != 88 || d.prev != 32767 {
		t.Fatalf("preset not clamped: %d %d", d.index, d.prev)
	}
	d.Preset(-5, -1<<20)
	if d.index != 0 || d.prev != -32768 {
		t.Fatalf("preset not clamped: %d %d", d.index, d.prev)
	}
}

func TestADPCMSilence(t *testing.T) {
	var d ADPCM
	out := d.Decode(nil, bytes.Repeat([]byte{0x88}, 100)) // code 8 = -0 → zero diff with sign
	for _, s := range out {
		if s < -8 || s > 8 {
			t.Fatalf("silence decoded to %d", s)
		}
	}
}

func sndFrame(flags byte, seq uint32, smeter uint16, audio []byte) []byte {
	b := []byte{flags}
	b = binary.LittleEndian.AppendUint32(b, seq)
	b = binary.BigEndian.AppendUint16(b, smeter)
	return append(b, audio...)
}

func TestParseSND(t *testing.T) {
	f, err := ParseSND(sndFrame(0x15, 42, 470, []byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	if f.Flags != 0x15 || f.Seq != 42 || f.SMeter != 470 || len(f.Audio) != 4 || !f.Compressed() {
		t.Fatalf("%+v", f)
	}
	if r := f.RSSI(); r < -80.01 || r > -79.99 {
		t.Fatalf("rssi %v", r)
	}
	// Endianness: seq LE, smeter BE, as the server writes them.
	raw := []byte{0, 0x01, 0x02, 0x03, 0x04, 0xAB, 0xCD}
	f, _ = ParseSND(raw)
	if f.Seq != 0x04030201 || f.SMeter != 0xABCD {
		t.Fatalf("endianness: seq=%x smeter=%x", f.Seq, f.SMeter)
	}

	bad := [][]byte{
		{},
		{0x10},
		sndFrame(0x10, 1, 1, nil)[:6],
		sndFrame(0x00, 1, 1, []byte{1, 2, 3}), // odd PCM
		sndFrame(0x08, 1, 1, []byte{1, 2, 3, 4, 5}), // stereo without GPS header
		sndFrame(0x10, 1, 1, make([]byte, MaxSNDPayload+1)),
	}
	for i, b := range bad {
		if _, err := ParseSND(b); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	// stereo with header is parsed, header skipped
	f, err = ParseSND(sndFrame(0x08, 1, 1, append(make([]byte, 10), 1, 2, 3, 4)))
	if err != nil || len(f.Audio) != 4 {
		t.Fatalf("stereo: %v %d", err, len(f.Audio))
	}
}

func TestDecodeAudioPCM(t *testing.T) {
	f := SNDFrame{Flags: 0, Audio: []byte{0x12, 0x34, 0xFF, 0xFE}}
	out := DecodeAudio(nil, &f, nil)
	if len(out) != 2 || out[0] != 0x1234 || out[1] != -2 {
		t.Fatalf("BE: %v", out)
	}
	f.Flags = FlagLittleEndian
	out = DecodeAudio(nil, &f, nil)
	if out[0] != 0x3412 || out[1] != -257 {
		t.Fatalf("LE: %v", out)
	}
}

func TestParseMSG(t *testing.T) {
	p, err := ParseMSG([]byte(" sample_rate=11998.99 badp=0 cfg_loaded  version_maj=1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 4 || p[0].Name != "sample_rate" || p[0].Value != "11998.99" || p[2].Name != "cfg_loaded" || p[2].HasEq {
		t.Fatalf("%+v", p)
	}
	// value containing '=' keeps everything after the first
	p, _ = ParseMSG([]byte(" a=b=c"))
	if p[0].Value != "b=c" {
		t.Fatalf("%+v", p)
	}
	// token cap
	_, err = ParseMSG([]byte(" " + bytes.NewBufferString("").String() + repeatTok(MaxMSGTokens+10)))
	if err == nil {
		t.Fatal("token cap not enforced")
	}
	if Unescape("a%20b%zz") != "a%20b%zz" {
		t.Fatal("bad escape should return input")
	}
	if Unescape("Kiwi%20Garden") != "Kiwi Garden" {
		t.Fatal("unescape")
	}
}

func repeatTok(n int) string {
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		b.WriteString("x=1 ")
	}
	return b.String()
}

func TestSampleRateOK(t *testing.T) {
	for _, ok := range []float64{12000, 11998.99, 12050, 20250.95, 20100} {
		if !SampleRateOK(ok) {
			t.Errorf("%v rejected", ok)
		}
	}
	for _, bad := range []float64{0, -12000, 8000, 11000, 13000, 44100, 48000, 1e9} {
		if SampleRateOK(bad) {
			t.Errorf("%v accepted", bad)
		}
	}
}

func FuzzParseSND(f *testing.F) {
	f.Add(sndFrame(0x15, 1, 470, bytes.Repeat([]byte{0x77}, 1024)))
	f.Add(sndFrame(0x00, 1, 470, bytes.Repeat([]byte{1, 2}, 100)))
	f.Add(sndFrame(0x08, 1, 470, make([]byte, 30)))
	f.Fuzz(func(t *testing.T, body []byte) {
		fr, err := ParseSND(body)
		if err != nil {
			return
		}
		var d ADPCM
		out := DecodeAudio(nil, &fr, &d)
		if fr.Compressed() && len(out) != 2*len(fr.Audio) {
			t.Fatalf("adpcm length %d vs %d", len(out), len(fr.Audio))
		}
		if !fr.Compressed() && len(out) != len(fr.Audio)/2 {
			t.Fatalf("pcm length %d vs %d", len(out), len(fr.Audio))
		}
		if len(fr.Audio) > MaxSNDPayload {
			t.Fatal("payload cap bypassed")
		}
	})
}

func FuzzADPCM(f *testing.F) {
	f.Add([]byte{0x77, 0xFF, 0x00, 0x88}, int32(0), int32(0))
	f.Fuzz(func(t *testing.T, in []byte, idx, prev int32) {
		var d ADPCM
		d.Preset(idx, prev)
		out := d.Decode(nil, in)
		if len(out) != 2*len(in) {
			t.Fatal("length")
		}
		if d.index < 0 || d.index > 88 || d.prev < -32768 || d.prev > 32767 {
			t.Fatalf("state escaped: %d %d", d.index, d.prev)
		}
	})
}

func FuzzParseMSG(f *testing.F) {
	f.Add([]byte(" sample_rate=12000 badp=0"))
	f.Add([]byte(""))
	f.Add([]byte("\xff\xfe=\x00"))
	f.Fuzz(func(t *testing.T, body []byte) {
		p, _ := ParseMSG(body)
		if len(p) > MaxMSGTokens {
			t.Fatal("token cap")
		}
	})
}
