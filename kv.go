package blockv

import (
	"errors"
	"io"
)

const (
	PROTOTYPE_KV = 1
	PROTONAME_KV = "kv"
)

func init() {
	err := RegisterProtocol(&KV{})
	if err != nil {
		panic(err)
	}
}

type KV struct {
	Key   string
	Value string
	iseof bool
	Protocol
}

func (kv *KV) Write(p []byte) (n int, err error) {
	if kv.iseof {
		err = io.EOF
		return
	}
	kl := p[0]
	if int(kl)+1 > len(p) {
		err = errors.New("write too short")
		return
	}
	vl := p[int(kl)+1]
	if int(vl)+1 > len(p) {
		err = errors.New("write too short")
		return
	}
	kv.Key = string(p[1 : int(kl)+1])
	kv.Value = string(p[int(kl)+2 : int(kl)+2+int(vl)])
	kv.iseof = true
	return int(kl) + 2 + int(vl), nil
}

func (kv *KV) Read(p []byte) (n int, err error) {
	if kv.iseof {
		err = io.EOF
		return
	}
	if len(p) < kv.Len() {
		err = errors.New("read buffer too short")
		return
	}
	p[0] = uint8(len(kv.Key))
	copy(p[1:], kv.Key)
	p[1+len(kv.Key)] = uint8(len(kv.Value))
	copy(p[1+len(kv.Key)+1:], kv.Value)
	kv.iseof = true
	return kv.Len(), nil
}

func (kv *KV) Len() int {
	return 1 + len(kv.Key) + 1 + len(kv.Value)
}

func (*KV) String() string {
	return PROTONAME_KV
}

func (kv *KV) Type() ProtoType {
	return PROTOTYPE_KV
}

func (kv *KV) Reset() {
	kv.iseof = false
}
