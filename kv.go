package blockv

import (
	"errors"
	"io"
)

const (
	PROTOTYPE_KV = 1
	PROTONAME_KV = "kv"
)

const (
	KV_OP_SET = iota
	KV_OP_DEL
)

func init() {
	err := RegisterProtocol(&KV{})
	if err != nil {
		panic(err)
	}
}

type KV struct {
	Operation uint8
	Key       string
	Value     string // Value will store the reason of del on KV_OP_DEL
	iseof     bool
	Protocol
}

func (kv *KV) Write(p []byte) (n int, err error) {
	if kv.iseof {
		err = io.EOF
		return
	}
	kv.Operation = p[0]
	p = p[1:]
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
	return 1 + int(kl) + 2 + int(vl), nil
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
	p[0] = kv.Operation
	p[1] = uint8(len(kv.Key))
	copy(p[2:], kv.Key)
	p[2+len(kv.Key)] = uint8(len(kv.Value))
	copy(p[2+len(kv.Key)+1:], kv.Value)
	kv.iseof = true
	return kv.Len(), nil
}

func (kv *KV) Len() int {
	return 1 + 1 + len(kv.Key) + 1 + len(kv.Value)
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

func (kv *KV) New() Protocol {
	return new(KV)
}
