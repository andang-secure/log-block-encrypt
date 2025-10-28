package model

import (
	"github.com/andang-secure/log-block-encrypt/global"
)

type BlockLogModelImpl interface {
	GetLogByBlockID(blockID string, logs *[]BlockLogModel) error
	GetLogByBlockIdAndLogId(blockID string, logID string, logs *BlockLogModel) error
	GetEndLog(blockID string, latestLog *BlockLogModel) error
	Create(newLog *BlockLogModel) error
}
type BlockLogModel struct {
	ID          int64  `json:"id" gorm:"column:id;type:SERIAL;primary_key" ` // ID
	LogID       int    `gorm:"column:log_id" db:"log_id" form:"log_id" json:"log_id"`
	LogData     string `gorm:"column:log_data" db:"log_data" form:"log_data" json:"log_data"`
	PrevHash    string `gorm:"column:prev_hash" db:"prev_hash" form:"prev_hash" json:"prev_hash"`
	CurrentHash string `gorm:"column:current_hash" db:"current_hash" form:"current_hash" json:"current_hash"`
	BlockID     string `gorm:"column:block_id" db:"block_id" form:"block_id" json:"block_id"`
	CreatedAt   int64
	UpdatedAt   int64
	DeletedAt   int64
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
