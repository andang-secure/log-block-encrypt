package global

import "gorm.io/gorm"

var DB *gorm.DB
var BlockHeaderTableName string
var BlockLogTableName string

const (
	LogTableName = "log"
	INIT_LOGHASH = "2d6f582ef301baf65f6fdfe15b7e20c344315dd448f776a9e8940084b84c371a"
)
