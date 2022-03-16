package blockv

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKV(t *testing.T) {
	kv := &KV{
		Key:   "hello",
		Value: "world",
	}
	w := SelectWriter()
	io.Copy(w, kv)
	t.Log(w.Len(), w.Bytes())
	kv2 := new(KV)
	io.Copy(kv2, bytes.NewReader(w.Bytes()))
	assert.Equal(t, kv.Key, kv2.Key)
	assert.Equal(t, kv.Value, kv2.Value)
}
