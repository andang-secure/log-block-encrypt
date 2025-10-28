package log_block

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/andang-secure/log-block-encrypt/global"
	"github.com/andang-secure/log-block-encrypt/model"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"testing"
	"time"
)

// setupTestDB 设置测试数据库
func setupTestDB() *gorm.DB {
	// 使用本地数据库文件而不是内存数据库
	db, err := gorm.Open(sqlite.Open("C:\\Users\\17612\\GolandProjects\\andang_cas_service\\kss.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}

	// 临时设置全局变量以便迁移
	oldHeaderTable := global.BlockHeaderTableName
	oldLogTable := global.BlockLogTableName
	global.BlockHeaderTableName = "cas_log_block_header"
	global.BlockLogTableName = "cas_log"

	// 自动迁移表结构
	err = db.AutoMigrate(&model.BlockHeaderModel{}, &model.BlockLogModel{})
	if err != nil {
		global.BlockHeaderTableName = oldHeaderTable
		global.BlockLogTableName = oldLogTable
		panic("failed to migrate database: " + err.Error())
	}

	// 恢复原来的值
	global.BlockHeaderTableName = oldHeaderTable
	global.BlockLogTableName = oldLogTable

	return db
}

// setupTestKey 生成测试用RSA密钥
func setupTestKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate RSA key")
	}
	return key
}

// TestNewLogChain 测试创建LogChain实例
func TestNewLogChain(t *testing.T) {
	db := setupTestDB()
	key := setupTestKey()

	// 测试正常情况
	conf := &LogChainConf{
		RootKey:              key,
		DB:                   db,
		BlockHeaderTableName: "cas_log_block_header",
		BlockLogTableName:    "cas_log",
	}

	lc, err := NewLogChain(conf)
	assert.NoError(t, err)
	assert.NotNil(t, lc)

	// 测试缺少DB的情况
	confWithoutDB := &LogChainConf{
		RootKey:              key,
		DB:                   nil,
		BlockHeaderTableName: "cas_log_block_header",
		BlockLogTableName:    "cas_log",
	}
	lc, err = NewLogChain(confWithoutDB)
	assert.Error(t, err)
	assert.Nil(t, lc)
	assert.Equal(t, "数据库连接未初始化", err.Error())

	// 测试缺少日志表名的情况
	confWithoutLogTable := &LogChainConf{
		RootKey:              key,
		DB:                   db,
		BlockHeaderTableName: "block_headers",
		BlockLogTableName:    "",
	}
	lc, err = NewLogChain(confWithoutLogTable)
	assert.Error(t, err)
	assert.Nil(t, lc)
	assert.Equal(t, "日志表名未设置", err.Error())

	// 测试缺少区块表名的情况
	confWithoutHeaderTable := &LogChainConf{
		RootKey:              key,
		DB:                   db,
		BlockHeaderTableName: "",
		BlockLogTableName:    "block_logs",
	}
	lc, err = NewLogChain(confWithoutHeaderTable)
	assert.Error(t, err)
	assert.Nil(t, lc)
	assert.Equal(t, "区块表名未设置", err.Error())

	// 测试缺少根密钥的情况
	confWithoutKey := &LogChainConf{
		RootKey:              nil,
		DB:                   db,
		BlockHeaderTableName: "cas_log_block_header",
		BlockLogTableName:    "cas_log",
	}
	lc, err = NewLogChain(confWithoutKey)
	assert.Error(t, err)
	assert.Nil(t, lc)
	assert.Equal(t, "根密钥未初始化", err.Error())
}

// TestCreateLog 测试创建日志功能
func TestCreateLog(t *testing.T) {

	db := setupTestDB()
	key := setupTestKey()

	conf := &LogChainConf{
		RootKey:              key,
		DB:                   db,
		BlockHeaderTableName: "cas_log_block_header",
		BlockLogTableName:    "cas_log",
	}

	lc, err := NewLogChain(conf)
	assert.NoError(t, err)
	assert.NotNil(t, lc)

	// 测试创建日志
	logData := "test log data"
	err = lc.CreateLog(logData)
	assert.NoError(t, err)

	// 测试空日志数据
	err = lc.CreateLog("")
	assert.Error(t, err)
	assert.Equal(t, "日志内容不能为空", err.Error())

	// 循环验证ID从1到10的日志
	for i := 1; i <= 10; i++ {
		log, err := lc.VerifyLog(i, "1761580800")
		if err != nil {
			// 如果日志不存在，跳出循环
			fmt.Printf("日志 %d 不存在\n", i)
		}
		assert.NoError(t, err)
		fmt.Printf("log %d: %v\n", i, log)
	}
	signature, err := lc.VerifyBlockchain(nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	// 验证签名不是空的
	assert.NotEqual(t, "", signature)
}

// TestSignBlockHeader 测试区块头签名功能
func TestSignBlockHeader(t *testing.T) {
	key := setupTestKey()

	header := &model.BlockHeaderModel{
		BlockID:        "1234567890",
		PrevBlockHash:  "prev_hash",
		MerkleRoot:     "merkle_root",
		BlockSignature: "",
		LogCount:       5,
	}

	lc := &LogChain{
		rootKey: key,
	}

	signature, err := lc.SignBlockHeader(header)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	// 验证签名不是空的
	assert.NotEqual(t, "", signature)
}

// TestVerifyBlockSignature 测试区块签名验证功能
func TestVerifyBlockSignature(t *testing.T) {
	key := setupTestKey()

	lc := &LogChain{
		rootKey: key,
	}

	// 先创建一个带签名的区块头
	header := &model.BlockHeaderModel{
		BlockID:        "1234567890",
		PrevBlockHash:  "prev_hash",
		MerkleRoot:     "merkle_root",
		BlockSignature: "",
		LogCount:       5,
	}

	signature, err := lc.SignBlockHeader(header)
	assert.NoError(t, err)

	header.BlockSignature = signature

	// 验证签名
	isValid := lc.verifyBlockSignature(header)
	assert.True(t, isValid)

	// 测试无效签名
	header.BlockSignature = "invalid_signature"
	isValid = lc.verifyBlockSignature(header)
	assert.False(t, isValid)

	// 测试空签名
	header.BlockSignature = ""
	isValid = lc.verifyBlockSignature(header)
	assert.False(t, isValid)
}

// TestGenerateBlockID 测试区块ID生成功能
func TestGenerateBlockID(t *testing.T) {
	id := generateBlockID()

	// 区块ID应该是今天的日期时间戳
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	expectedID := todayStart.Unix()

	assert.Equal(t, expectedID, int64(len(id)))
	assert.NotEmpty(t, id)
}

// TestCreateNewBlock 测试创建新区块功能
func TestCreateNewBlock(t *testing.T) {

	db := setupTestDB()
	key := setupTestKey()

	conf := &LogChainConf{
		RootKey:              key,
		DB:                   db,
		BlockHeaderTableName: "block_headers",
		BlockLogTableName:    "block_logs",
	}

	lc, err := NewLogChain(conf)
	assert.NoError(t, err)
	assert.NotNil(t, lc)

	block, err := lc.createNewBlock()
	assert.NoError(t, err)
	assert.NotNil(t, block)
	assert.NotEmpty(t, block.BlockID)
	assert.Equal(t, global.INIT_LOGHASH, block.PrevBlockHash)
	assert.Equal(t, "", block.MerkleRoot)
	assert.Equal(t, "", block.BlockSignature)
	assert.Equal(t, 0, block.LogCount)
}

// TestUpdateMerkleRoot 测试更新Merkle根功能
func TestUpdateMerkleRoot(t *testing.T) {
	db := setupTestDB()
	key := setupTestKey()

	conf := &LogChainConf{
		RootKey:              key,
		DB:                   db,
		BlockHeaderTableName: "block_headers",
		BlockLogTableName:    "block_logs",
	}

	lc, err := NewLogChain(conf)
	assert.NoError(t, err)
	assert.NotNil(t, lc)

	// 创建一个区块
	block := &model.BlockHeaderModel{
		BlockID:        "1234567890",
		PrevBlockHash:  "prev_hash",
		MerkleRoot:     "",
		BlockSignature: "",
		LogCount:       0,
	}

	// 调用updateMerkleRoot之前Merkle根应为空
	assert.Equal(t, "", block.MerkleRoot)

	// 因为没有日志，Merkle根应该仍然为空
	lc.updateMerkleRoot(block)
	// 注意：这里的行为取决于utils.BuildMerkleTree对于空数组的处理方式
}
