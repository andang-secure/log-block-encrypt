package model

import (
	"chain_log_demo/global"
	"time"
)

type BlockHeaderModelImpl interface {
	GetAll(unsealedBlocks []BlockHeaderModel) error
	GetIdBySignature(headers []BlockHeaderModel) error
	Update(BlockID string, signature string) error
	GetBlocksByID(blockID string, header *BlockHeaderModel) error
	GetBlockCount() (count int64, err error)
	GetLatestBlock(latestBlock *BlockHeaderModel) error
	GetOrCreateBlock(bh *BlockHeaderModel) error
	UpdateCurrentBlock(currentBlock *BlockHeaderModel) error
}

type BlockHeaderModel struct {
	ID             uint   `gorm:"primaryKey"`
	BlockID        string `gorm:"uniqueIndex"`
	PrevBlockHash  string
	MerkleRoot     string
	BlockSignature string
	LogCount       int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (t *BlockHeaderModel) TableName() string {
	return global.BlockHeaderTableName
}

// GetAll  任务信息
func (t *BlockHeaderModel) GetAll(unsealedBlocks []BlockHeaderModel) error {
	if err := global.DB.Table(t.TableName()).Unscoped().Where("is_sealed = ?", false).Find(&unsealedBlocks).Error; err != nil {
		return err
	}
	return nil
}

func (t *BlockHeaderModel) GetIdBySignature(headers []BlockHeaderModel) error {
	if err := global.DB.Table(t.TableName()).Unscoped().Where("block_signature != ?", "").Order("block_id asc").Find(&headers).Error; err != nil {
		return err
	}
	return nil
}

func (t *BlockHeaderModel) Update(blockID string, signature string) error {
	// 更新数据库中的区块状态为已封块
	if err := global.DB.Table(t.TableName()).Unscoped().Where("block_id = ?", blockID).Updates(map[string]interface{}{
		"is_sealed":       true,
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
