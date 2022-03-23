package blockv

import (
	"io"
	"os"
	"strconv"
	"sync"

	sql "github.com/FloatTech/sqlite"
	base14 "github.com/fumiama/go-base16384"
)

type Storage struct {
	sync.RWMutex
	blkn   int
	db     sql.Sqlite
	folder string
}

type info struct {
	ID  int    `db:"id"`  // ID will increase from 0
	Pub string `db:"pub"` // Pub is the b14 pub in a block
}

type kv struct {
	Key string `db:"key"`
	Val string `db:"val"`
}

func NewStorage(folder string) (*Storage, error) {
	err := os.MkdirAll(folder, 0755)
	if err != nil {
		return nil, err
	}
	s := new(Storage)
	s.folder = folder
	s.db.DBPath = folder + "/kv.db"
	err = s.db.Open()
	if err != nil {
		return nil, err
	}
	err = s.db.Create("info", &info{})
	if err != nil {
		return nil, err
	}
	err = s.db.Create("kv", &kv{})
	if err != nil {
		return nil, err
	}
	n, err := s.db.Count("info")
	if err != nil {
		return nil, err
	}
	s.blkn = n
	return s, nil
}

func (s *Storage) VerifyAllBlocks() error {
	s.RLock()
	defer s.RUnlock()
	var prevb *Block
	for i := 0; i < s.blkn; i++ {
		data, err := os.ReadFile(s.folder + "/" + strconv.FormatInt(int64(i), 36))
		if err != nil {
			return err
		}
		b, err := ParseBlock(data)
		if err != nil {
			return err
		}
		_, err = b.Verify(prevb)
		if err != nil {
			return err
		}
		prevb = b
	}
	return nil
}

func (s *Storage) AppendBlock(b *Block) error {
	s.Lock()
	defer s.Unlock()
	n := s.blkn
	f, err := os.Create(s.folder + "/" + strconv.FormatInt(int64(n), 36))
	if err != nil {
		return err
	}
	buf := b.Buffer()
	_, err = io.Copy(f, &buf)
	if err != nil {
		return err
	}
	err = s.db.Insert("info", &info{
		ID:  n,
		Pub: base14.EncodeString(base14.BytesToString(b.pub[:])),
	})
	if err != nil {
		return err
	}
	s.blkn++
	return nil
}

func (s *Storage) Set(k, v string) (err error) {
	s.Lock()
	defer s.Unlock()
	err = s.db.Insert("kv", &kv{
		Key: k,
		Val: v,
	})
	return
}

func (s *Storage) Get(k string) (v string, err error) {
	kvs := kv{}
	s.RLock()
	defer s.RUnlock()
	err = s.db.Find("kv", &kvs, "WHERE key='"+k+"'")
	v = kvs.Val
	return
}
