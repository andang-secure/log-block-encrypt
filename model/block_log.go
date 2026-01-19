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
	PrevHash    string `gorm:"column:prev_hash" db:"prev_hash" form:"prev_hash" json:"prev_hash"`
	CurrentHash string `gorm:"column:current_hash" db:"current_hash" form:"current_hash" json:"current_hash"`
	// 核心：为block_id指定相同名称的复合索引idx_blockid_logid
	BlockID    string `gorm:"column:block_id" db:"block_id" form:"block_id" json:"block_id"`
	CreatedAt  int64  `json:"created_at"`                                                // 创建时间
	UpdatedAt  int64  `json:"updated_at"`                                                // 修改时间
	Name       string `gorm:"column:name" db:"name" json:"name" form:"name"`             //账号名称
	EnName     string `gorm:"column:en_name" db:"en_name" json:"en_name" form:"en_name"` //英文名称
	URL        string `gorm:"column:url" db:"url" json:"url" form:"url"`                 //账号名称
	Method     string `gorm:"column:method" db:"method" json:"method" form:"method"`     //备注
	Data       string `gorm:"column:data" db:"data" json:"data" form:"data"`
	UID        int64  `gorm:"column:uid" db:"uid" json:"uid" form:"uid"`
	Uname      string `gorm:"column:uname" db:"uname" json:"uname" form:"uname"`
	RequestID  string `gorm:"column:request_id" db:"request_id" json:"request_id" form:"request_id"`
	Type       int    `gorm:"column:type" db:"type" json:"type" form:"type"` // 0:web 1:open
	RemoteIP   string `gorm:"column:remote_ip" db:"remote_ip" json:"remote_ip" form:"remote_ip"`
	ProjectID  int64  `gorm:"column:project_id" db:"project_id" json:"project_id" form:"project_id"`
	Result     string `gorm:"column:result" db:"result" json:"result" form:"result"`
	EnResult   string `gorm:"column:en_result" db:"en_result" json:"en_result" form:"en_result"`
	HaxEqually int    `gorm:"-" db:"-" json:"hax_equally" form:"hax_equally"` // 哈希验证标记，是否和LogUnique一致
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

	if err := global.DB.Table(b.TableName()).
		Select("id, block_id, log_id, prev_hash, current_hash").
		Where("block_id = ?", blockID).
		Order("log_id DESC").
		Limit(1).
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
