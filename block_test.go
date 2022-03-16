package blockv

import (
	"testing"
)

func TestBlock(t *testing.T) {
	b, err := NewBlock(&KV{
		Key:   "hello",
		Value: "world",
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMe("0.0.0.0:8000", "", "")
	if err != nil {
		t.Fatal(err)
	}
	err = m.Close()
	if err != nil {
		t.Fatal(err)
	}
	err = b.Sign(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := NewBlock(&KV{
		Key:   "hello2",
		Value: "world2",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = b2.Sign(m, b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b2.Verify(b)
	if err != nil {
		t.Fatal(err)
	}
}
