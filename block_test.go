package blockv

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBlock(t *testing.T) {
	b, err := NewBlock(&KV{
		Key:   "hello",
		Value: "world",
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMe("test", "0.0.0.0:8000", "", "", "pwd", "")
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
	w := SelectWriter()
	buf := b2.Buffer()
	_, err = io.Copy(w, &buf)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := ParseBlock(w.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	kvproto := b3.pro[0].(*KV)
	assert.Equal(t, uint8(KV_OP_SET), kvproto.Operation)
	assert.Equal(t, "hello2", kvproto.Key)
	assert.Equal(t, "world2", kvproto.Value)
}
