package db

import (
	"log"

	"github.com/siddontang/ledisdb/config"
	"github.com/siddontang/ledisdb/ledis"
)

var db *ledis.DB

// Connect DB
func Connect() {
	// 資料的儲存位置設定到 ./db-data
	cfg := config.NewConfigDefault()
	cfg.DataDir = "./db_data"

	// 建立連線
	l, _ := ledis.Open(cfg)
	_db, err := l.Select(0)
	if err != nil {
		panic(err)
	}

	db = _db
	log.Println("Connect to db successfully")
}

//Insert data
func Insert(s string) {
	// fishes 是這個 list 的名字（key）
	fishes := []byte("fishes")

	// 把字串 s 加到 fishes 裡面
	db.RPush(fishes, []byte(s))
}

//SelectAll data from DB
func SelectAll() []string {
	fishes := []byte("fishes")
	// list 長度
	nFish, _ := db.LLen(fishes)
	// list 取資料
	datas, _ := db.LRange(fishes, 0, int32(nFish))
	// 取出來資料型別為 []byte 轉型成 string 放到 strs
	strs := []string{}
	for _, data := range datas {
		strs = append(strs, string(data))
	}
	return strs
}

// DelAll data of DB
func DelAll() {
	db.LClear([]byte("fishes"))
}
