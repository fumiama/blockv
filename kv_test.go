package blockv

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKV(t *testing.T) {
	kv := &KV{
		Operation: KV_OP_DEL,
		Key:       "hello",
		Value:     "boring",
	}
	w := SelectWriter()
	io.Copy(w, kv)
	t.Log(w.Len(), w.Bytes())
	kv2 := new(KV)
	io.Copy(kv2, bytes.NewReader(w.Bytes()))
	assert.Equal(t, uint8(KV_OP_DEL), kv.Operation)
	assert.Equal(t, kv.Key, kv2.Key)
	assert.Equal(t, kv.Value, kv2.Value)
}
