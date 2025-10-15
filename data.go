package main

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// GORM 模型
type LogModel struct {
	ID          uint   `gorm:"primaryKey"`
	LogID       string `gorm:"uniqueIndex;size:32"`
	Time        int64
	Operator    string `gorm:"size:64"`
	KeyID       string `gorm:"size:64"`
	Action      string `gorm:"size:32"`
	Content     string `gorm:"type:text"`
	PrevHash    string `gorm:"size:128"`
	CurrentHash string `gorm:"size:128"`
	Valid       bool
	BlockID     string `gorm:"index;size:32"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type BlockHeaderModel struct {
	ID             uint   `gorm:"primaryKey"`
	BlockID        string `gorm:"uniqueIndex"`
	PrevBlockHash  string
	MerkleRoot     string
	BlockSignature string
	LogCount       int
	IsSealed       bool `gorm:"default:false"` // 标识区块是否已被封块
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type BlockBodyModel struct {
	ID        uint   `gorm:"primaryKey"`
	BlockID   string `gorm:"uniqueIndex;size:32"`
	LogsJSON  string `gorm:"type:text"` // 可选：冗余存储完整日志体 JSON
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Database struct {
	DB *gorm.DB
}

func InitDatabase(path string) (*Database, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&LogModel{}, &BlockHeaderModel{}, &BlockBodyModel{}); err != nil {
		return nil, err
	}
	return &Database{DB: db}, nil
}
