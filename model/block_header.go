package model

import (
	"github.com/andang-secure/log-block-encrypt/global"
	"time"
)

type BlockHeaderModelImpl interface {
	GetNotSealedAll(unsealedBlocks *[]BlockHeaderModel) error
	GetIdBySignature(headers *[]BlockHeaderModel) error
	Update(BlockID string, signature string) error
	GetBlocksByID(blockID string, header *BlockHeaderModel) error
	GetBlockCount() (count int64, err error)
	GetLatestBlock(latestBlock *BlockHeaderModel) error
	GetOrCreateBlock(bh *BlockHeaderModel) error
	UpdateCurrentBlock(currentBlock *BlockHeaderModel) error
}

type BlockHeaderModel struct {
	ID             int64     `json:"id" gorm:"column:id;type:SERIAL;primary_key" ` // ID
	BlockID        string    `gorm:"column:block_id" db:"block_id" form:"block_id" json:"block_id"`
	PrevBlockHash  string    `gorm:"column:prev_block_hash" db:"prev_block_hash" form:"prev_block_hash" json:"prev_block_hash"`
	MerkleRoot     string    `gorm:"column:merkle_root" db:"merkle_root" form:"merkle_root" json:"merkle_root"`
	BlockSignature string    `gorm:"column:block_signature" db:"block_signature" form:"block_signature" json:"block_signature"`
	LogCount       int       `gorm:"column:log_count" db:"log_count" form:"log_count" json:"log_count"`
	CreatedAt      time.Time `gorm:"column:log_count" db:"log_count" form:"log_count" json:"log_count"`
	UpdatedAt      time.Time
}

func (t *BlockHeaderModel) TableName() string {
	return global.BlockHeaderTableName
}

// GetAll  任务信息
func (t *BlockHeaderModel) GetNotSealedAll(unsealedBlocks *[]BlockHeaderModel) error {
	if err := global.DB.Table(t.TableName()).Unscoped().Where("is_sealed = ?", false).Find(&unsealedBlocks).Error; err != nil {
		return err
	}
	return nil
}

func (t *BlockHeaderModel) GetIdBySignature(headers *[]BlockHeaderModel) error {
	if err := global.DB.Table(t.TableName()).Unscoped().Where("block_signature != ?", "").Order("block_id asc").Find(&headers).Error; err != nil {
		return err
	}
	return nil
}

func (t *BlockHeaderModel) Update(blockID string, signature string) error {
	// 更新数据库中的区块状态为已封块
	if err := global.DB.Table(t.TableName()).Unscoped().Where("block_id = ?", blockID).Updates(map[string]interface{}{
		"block_signature": signature,
	}).Error; err != nil {
		return err
	}
	return nil
}

func (t *BlockHeaderModel) GetBlocksByID(blockID string, header *BlockHeaderModel) error {
	if err := global.DB.Table(t.TableName()).Unscoped().Where("block_id = ?", blockID).First(&header).Error; err == nil {
		return err
	}
	return nil
}

func (t *BlockHeaderModel) GetBlockCount() (count int64, err error) {
	if err := global.DB.Table(t.TableName()).Unscoped().Count(&count).Error; err == nil {
		return 0, err
	}
	return count, nil
}

func (t *BlockHeaderModel) GetLatestBlock(latestBlock *BlockHeaderModel) error {
	if err := global.DB.Table(t.TableName()).Order("block_id desc").First(&latestBlock).Error; err == nil {
		return err
	}
	return nil
}

func (t *BlockHeaderModel) GetOrCreateBlock(bh *BlockHeaderModel) error {
	if err := global.DB.Table(t.TableName()).Where("block_id = ?", bh.BlockID).Assign(bh).FirstOrCreate(bh).Error; err == nil {
		return err
	}
	return nil
}

func (t *BlockHeaderModel) UpdateCurrentBlock(currentBlock *BlockHeaderModel) error {
	if err := global.DB.Table(t.TableName()).Unscoped().Where("block_id = ?", currentBlock.BlockID).Updates(map[string]interface{}{
		"log_count":       currentBlock.LogCount,
		"merkle_root":     currentBlock.MerkleRoot,
		"block_signature": currentBlock.BlockSignature,
	}).Error; err != nil {
		return err
	}
	return nil
}
