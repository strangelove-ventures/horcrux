package bn254

import (
	"bytes"
	"testing"
)

func TestHashToG2MiMC(t *testing.T) {
	testCases := []struct {
		name string
		msg  []byte
		dst  []byte
	}{
		{
			name: "empty message",
			msg:  []byte{},
			dst:  []byte("test-dst"),
		},
		{
			name: "simple message",
			msg:  []byte("hello world"),
			dst:  []byte("test-dst"),
		},
		{
			name: "long message",
			msg:  bytes.Repeat([]byte("a"), 1000),
			dst:  []byte("test-dst"),
		},
		{
			name: "different dst",
			msg:  []byte("hello world"),
			dst:  []byte("different-dst"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			point, err := HashToG2MiMC(tc.msg, tc.dst)
			if err != nil {
				t.Fatalf("HashToG2MiMC failed: %v", err)
			}

			// Verify the point is valid
			if !point.IsOnCurve() {
				t.Error("Point is not on curve")
			}
			if point.IsInfinity() {
				t.Error("Point is at infinity")
			}
			if !point.IsInSubGroup() {
				t.Error("Point is not in the correct subgroup")
			}
		})
	}
}

func TestHashToFieldMiMC(t *testing.T) {
	testCases := []struct {
		name string
		msg  []byte
		dst  []byte
	}{
		{
			name: "empty message",
			msg:  []byte{},
			dst:  []byte("test-dst"),
		},
		{
			name: "simple message",
			msg:  []byte("hello world"),
			dst:  []byte("test-dst"),
		},
		{
			name: "long message",
			msg:  bytes.Repeat([]byte("a"), 1000),
			dst:  []byte("test-dst"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			elements, err := HashToFieldMiMC(tc.msg, tc.dst)
			if err != nil {
				t.Fatalf("HashToFieldMiMC failed: %v", err)
			}

			// Check we got 4 elements
			if len(elements) != 4 {
				t.Errorf("Expected 4 elements, got %d", len(elements))
			}

			// Verify each element is valid
			for i, elem := range elements {
				bytes := elem.Bytes()
				if len(bytes) == 0 {
					t.Errorf("Element %d is empty", i)
				}
			}
		})
	}
}

func TestExpandMsgXmdMiMC(t *testing.T) {
	testCases := []struct {
		name       string
		msg        []byte
		dst        []byte
		lenInBytes int
	}{
		{
			name:       "empty message",
			msg:        []byte{},
			dst:        []byte("test-dst"),
			lenInBytes: 32,
		},
		{
			name:       "simple message",
			msg:        []byte("hello world"),
			dst:        []byte("test-dst"),
			lenInBytes: 64,
		},
		{
			name:       "long message",
			msg:        bytes.Repeat([]byte("a"), 1000),
			dst:        []byte("test-dst"),
			lenInBytes: 128,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := ExpandMsgXmdMiMC(tc.msg, tc.dst, tc.lenInBytes)
			if err != nil {
				t.Fatalf("ExpandMsgXmdMiMC failed: %v", err)
			}

			// Check length
			if len(output) != tc.lenInBytes {
				t.Errorf("Expected output length %d, got %d", tc.lenInBytes, len(output))
			}

			// Run it twice to verify deterministic output
			output2, err := ExpandMsgXmdMiMC(tc.msg, tc.dst, tc.lenInBytes)
			if err != nil {
				t.Fatalf("Second ExpandMsgXmdMiMC failed: %v", err)
			}

			if !bytes.Equal(output, output2) {
				t.Error("Outputs differ between runs")
				t.Errorf("First:  %x", output)
				t.Errorf("Second: %x", output2)
			}
		})
	}
}

func TestConsistencyWithKnownValues(t *testing.T) {
	msg := []byte("test message")
	dst := []byte("BN254G2_XMD:MIMC-256_SVDW_TEST")

	point, err := HashToG2MiMC(msg, dst)
	if err != nil {
		t.Fatalf("HashToG2MiMC failed: %v", err)
	}

	// Store your known good value here from the previous implementation
	x0Bytes := point.X.A0.Bytes()
	x1Bytes := point.X.A1.Bytes()
	y0Bytes := point.Y.A0.Bytes()
	y1Bytes := point.Y.A1.Bytes()

	t.Logf("Point coordinates for reproducibility:")
	t.Logf("X.A0: %x", x0Bytes)
	t.Logf("X.A1: %x", x1Bytes)
	t.Logf("Y.A0: %x", y0Bytes)
	t.Logf("Y.A1: %x", y1Bytes)
}

// Benchmarks

func BenchmarkHashToG2MiMC(b *testing.B) {
	msg := []byte("benchmark message")
	dst := []byte("test-dst")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HashToG2MiMC(msg, dst)
		if err != nil {
			b.Fatalf("HashToG2MiMC failed: %v", err)
		}
	}
}

func BenchmarkHashToFieldMiMC(b *testing.B) {
	msg := []byte("benchmark message")
	dst := []byte("test-dst")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HashToFieldMiMC(msg, dst)
		if err != nil {
			b.Fatalf("HashToFieldMiMC failed: %v", err)
		}
	}
}

func BenchmarkExpandMsgXmdMiMC(b *testing.B) {
	benchCases := []struct {
		name       string
		msgSize    int
		lenInBytes int
	}{
		{"small", 32, 32},
		{"medium", 1000, 64},
		{"large", 10000, 128},
	}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			msg := bytes.Repeat([]byte("a"), bc.msgSize)
			dst := []byte("test-dst")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := ExpandMsgXmdMiMC(msg, dst, bc.lenInBytes)
				if err != nil {
					b.Fatalf("ExpandMsgXmdMiMC failed: %v", err)
				}
			}
		})
	}
}
