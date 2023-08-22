package pcosigner

import (
	"reflect"
	"testing"
)

func TestThresholdSignerSoft_GenerateNonces(t *testing.T) {
	type fields struct {
		privateKeyShard []byte
		pubKey          []byte
		threshold       uint8
		total           uint8
	}
	tests := []struct {
		name    string
		fields  fields
		want    Nonces
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ThresholdSignerSoft{
				privateKeyShard: tt.fields.privateKeyShard,
				pubKey:          tt.fields.pubKey,
				threshold:       tt.fields.threshold,
				total:           tt.fields.total,
			}
			got, err := s.GenerateNonces()
			if (err != nil) != tt.wantErr {
				t.Errorf("ThresholdSignerSoft.GenerateNonces() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ThresholdSignerSoft.GenerateNonces() = %v, want %v", got, tt.want)
			}
		})
	}
}
