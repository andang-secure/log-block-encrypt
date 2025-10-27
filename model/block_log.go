package model

import (
	"github.com/andang-secure/log-block-encrypt/global"
	"time"
)

type BlockLogModelImpl interface {
	GetLogByBlockID(blockID string, logs *[]BlockLogModel) error
	GetLogByBlockIdAndLogId(blockID string, logID string, logs *BlockLogModel) error
	GetEndLog(blockID string, latestLog *BlockLogModel) error
	Create(newLog *BlockLogModel) error
}
type BlockLogModel struct {
	ID          uint `gorm:"primaryKey"`
	LogID       int  `gorm:"index;size:32"`
	LogData     string
	PrevHash    string
	CurrentHash string
	BlockID     string `gorm:"index;size:32"`
	CreatedAt   int64
	UpdatedAt   time.Time
}

func (b *BlockLogModel) TableName() string {
	return global.BlockLogTableName
}

// GetLogByBlockID  任务信息
func (b *BlockLogModel) GetLogByBlockID(blockID string, logs *[]BlockLogModel) error {
	if err := global.DB.Table(b.TableName()).Unscoped().Where("block_id = ?", blockID).Find(&logs).Error; err != nil {
		return err
	}
	return nil
}

func (b *BlockLogModel) GetLogByBlockIdAndLogId(blockID string, logID string, logs *BlockLogModel) error {
	if err := global.DB.Table(b.TableName()).Unscoped().Where("block_id = ?", blockID).Where("log_id = ?", logID).Order("id asc").Find(&logs).Error; err != nil {
		return err
	}
	return nil
}

func (b *BlockLogModel) GetEndLog(blockID string, latestLog *BlockLogModel) error {
	if err := global.DB.Table(b.TableName()).Unscoped().Where("block_id = ?", blockID).
		Order("log_id DESC").
		First(&latestLog).Error; err != nil {
		return err
	}
	return nil
}

func (b *BlockLogModel) Create(newLog *BlockLogModel) error {
	if err := global.DB.Table(b.TableName()).Unscoped().Create(&newLog).Error; err != nil {
		return err
	}
	return nil
}
