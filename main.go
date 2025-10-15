package main

import (
	"crypto"
	r2 "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 日志结构体定义（格式：LOG+区块ID+3位序号，如：LOGBLK1234567890001，共19位）
type Log struct {
	LogID       string // 日志唯一标识
	Time        int64  // 操作时间戳（毫秒）
	Operator    string // 操作人
	KeyID       string // 密钥ID
	Action      string // 操作类型（generate/use/destroy/import）
	Content     string // 操作内容
	PrevHash    string // 前一条日志的哈希
	CurrentHash string // 当前日志的哈希
	Valid       bool   // 哈希验证标记
}

// 区块头结构体（BlockID：13位，BLK+10位秒级时间戳，按分钟对齐）
type BlockHeader struct {
	BlockID        string // 区块唯一标识
	PrevBlockHash  string // 前一个区块头的哈希
	MerkleRoot     string // 区块内日志的Merkle树根值
	BlockSignature string // 根密钥对区块头的签名
	LogCount       int    // 区块内日志数量
}

// 修改 BlockVerificationResult 结构体，移除 ChainValid 字段（因为单个区块无法验证链连接）
type BlockVerificationResult struct {
	BlockID        string   `json:"blockId"`
	Valid          bool     `json:"valid"`
	TamperedLogs   []string `json:"tamperedLogs,omitempty"` // 被篡改的日志ID列表
	SignatureValid bool     `json:"signatureValid"`
	MerkleValid    bool     `json:"merkleValid"`
}

// 区块体结构体
type BlockBody struct {
	BlockID string // 与区块头BlockID一致
	Logs    []*Log // 区块内存储的日志列表
}

// 区块结构体
type Block struct {
	Header *BlockHeader // 区块核心验证信息
	Body   *BlockBody   // 区块原始数据
}

// KSS系统结构体（管理区块、密钥和随机阈值）
type KSSSystem struct {
	CurrentBlock       *Block            // 当前未封块的区块
	Blocks             map[string]*Block // 已封块存储（key：BlockID）
	RootKey            *rsa.PrivateKey   // 根密钥（实际需HSM存储）
	currentLogCount    int               // 当前区块已存日志数
	randomBlockSize    int               // 当前区块的随机日志阈值（3-8条）
	currentBlockMinute int64             // 当前区块开始的分钟（用于跨分钟强制切换区块）
}

// 初始化KSS系统（初始化随机数种子和初始阈值）
func NewKSSSystem(rootKey *rsa.PrivateKey) *KSSSystem {
	rand.Seed(time.Now().UnixNano()) // 确保随机阈值每次运行不同
	return &KSSSystem{
		Blocks:          make(map[string]*Block),
		RootKey:         rootKey,
		randomBlockSize: generateRandomBlockSize(), // 初始随机阈值（3-8）
	}
}

// 生成随机区块大小（3-8条日志，可按需调整范围）
func generateRandomBlockSize() int {
	return rand.Intn(6) + 3 // Intn(6)生成0-5，+3后范围为3-8
}

// 生成区块ID（格式：BLK+10位秒级时间戳，按分钟对齐）
func generateBlockID() string {
	// 获取当前时间并对齐到分钟（秒和纳秒设为0）
	now := time.Now()
	minuteAligned := time.Date(now.Year(), now.Month(), now.Day(),
		now.Hour(), now.Minute(), 0, 0, now.Location())
	timestamp := minuteAligned.Unix() // 10位秒级时间戳，对齐到分钟
	return fmt.Sprintf("BLK%d", timestamp)
}

// 从区块ID中提取时间戳（格式：BLK+10位秒级时间戳）
func extractTimestampFromBlockID(blockID string) int64 {
	if len(blockID) < 13 || !strings.HasPrefix(blockID, "BLK") {
		return 0
	}
	var timestamp int64
	fmt.Sscanf(blockID[3:], "%d", &timestamp)
	return timestamp
}

// 计算字符串的SHA-256哈希（返回16进制字符串）
func calculateHash(data string) string {
	hashBytes := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hashBytes[:])
}

// 生成日志的哈希（基于日志核心字段，确保内容篡改能被检测）
func (log *Log) GenerateHash() string {
	// 拼接日志关键字段（不可篡改字段：LogID、Time、Operator、KeyID、Action、Content）
	hashSource := fmt.Sprintf(
		"logId=%s&time=%d&operator=%s&keyId=%s&action=%s&content=%s",
		log.LogID, log.Time, log.Operator, log.KeyID, log.Action, log.Content,
	)
	return calculateHash(hashSource)
}

// 创建新日志（核心逻辑：按每分钟时间戳判断是否封块）
func (kss *KSSSystem) CreateLog(operator, keyID, action, content string) *Log {
	// 1. 若当前无区块，初始化新区块
	if kss.CurrentBlock == nil {
		kss.createNewBlock()
		// 如果这是新区块的第一条日志，立即在数据库中创建区块记录
		if dbStore != nil && dbStore.DB != nil {
			bh := &BlockHeaderModel{
				BlockID:        kss.CurrentBlock.Header.BlockID,
				PrevBlockHash:  kss.CurrentBlock.Header.PrevBlockHash,
				MerkleRoot:     kss.CurrentBlock.Header.MerkleRoot,
				BlockSignature: "", // 新区块还没有签名
				LogCount:       kss.CurrentBlock.Header.LogCount,
				IsSealed:       false, // 新创建的区块未被封块
			}
			dbStore.DB.Where("block_id = ?", bh.BlockID).Assign(bh).FirstOrCreate(bh)
		}
	}

	// 2. 判断当前区块是否应该封块：检查当前分钟是否已过区块 ID 代表的分钟
	currentMinuteTimestamp := time.Now().Unix() / 60 * 60                                // 当前分钟的秒级时间戳（对齐到分钟）
	blockMinuteTimestamp := extractTimestampFromBlockID(kss.CurrentBlock.Header.BlockID) // 区块 ID 中的时间戳

	// 如果当前时间已经过了区块ID代表的分钟，且区块有日志，则封块
	if currentMinuteTimestamp > blockMinuteTimestamp && kss.CurrentBlock.Header.LogCount > 0 {
		if err := kss.finalizeBlock(); err != nil {
			log.Printf("封块警告：%v（继续使用当前区块）", err)
		} else {
			// 持久化到数据库
			if dbStore != nil && dbStore.DB != nil {
				_ = persistBlock(dbStore.DB, kss.Blocks[kss.CurrentBlock.Header.BlockID])
				// 更新数据库中的区块状态为已封块
				dbStore.DB.Model(&BlockHeaderModel{}).Where("block_id = ?", kss.CurrentBlock.Header.BlockID).Update("is_sealed", true)
			}
			// 清空当前区块
			kss.CurrentBlock = nil
			kss.currentLogCount = 0
		}
		// 在需要时再创建新区块
		if kss.CurrentBlock == nil {
			kss.createNewBlock()
			// 如果这是新区块的第一条日志，立即在数据库中创建区块记录
			if dbStore != nil && dbStore.DB != nil {
				bh := &BlockHeaderModel{
					BlockID:        kss.CurrentBlock.Header.BlockID,
					PrevBlockHash:  kss.CurrentBlock.Header.PrevBlockHash,
					MerkleRoot:     kss.CurrentBlock.Header.MerkleRoot,
					BlockSignature: "", // 新区块还没有签名
					LogCount:       kss.CurrentBlock.Header.LogCount,
					IsSealed:       false, // 新创建的区块未被封块
				}
				dbStore.DB.Where("block_id = ?", bh.BlockID).Assign(bh).FirstOrCreate(bh)
			}
		}
	}

	// 3. 生成日志ID（LOG+区块ID+3位序号，如：LOGBLK1234567890001）
	blockID := kss.CurrentBlock.Header.BlockID
	logSeq := fmt.Sprintf("%03d", kss.currentLogCount+1) // 日志在区块内的序号（001-008）
	logID := fmt.Sprintf("LOG%s%s", blockID, logSeq)     // 完整日志ID

	// 4. 计算前一条日志的哈希（确保日志间链式关联）
	var prevLogHash string
	// 确保当前区块有日志且索引有效
	if kss.currentLogCount > 0 && len(kss.CurrentBlock.Body.Logs) > 0 {
		// 确保 currentLogCount 不超过实际日志数量
		if kss.currentLogCount <= len(kss.CurrentBlock.Body.Logs) {
			prevLog := kss.CurrentBlock.Body.Logs[kss.currentLogCount-1]
			prevLogHash = prevLog.CurrentHash
		}
	}

	// 5. 初始化日志并计算当前哈希
	newLog := &Log{
		LogID:    logID,
		Time:     time.Now().UnixMilli(),
		Operator: operator,
		KeyID:    keyID,
		Action:   action,
		Content:  content,
		PrevHash: prevLogHash,
		Valid:    true,
	}
	newLog.CurrentHash = newLog.GenerateHash() // 计算日志哈希

	// 6. 将日志添加到当前区块，并更新计数和Merkle根
	kss.CurrentBlock.Body.Logs = append(kss.CurrentBlock.Body.Logs, newLog)
	kss.currentLogCount++
	kss.CurrentBlock.Header.LogCount = kss.currentLogCount
	kss.updateMerkleRoot() // 实时更新区块的Merkle根

	// 7. 每次添加日志后都对区块头进行签名
	signature, err := kss.signBlockHeader(kss.CurrentBlock.Header)
	if err != nil {
		log.Printf("区块头签名失败：%v", err)
	} else {
		kss.CurrentBlock.Header.BlockSignature = signature
	}

	// 8. 更新数据库中的区块信息（包括签名）
	if dbStore != nil && dbStore.DB != nil {
		updates := map[string]interface{}{
			"log_count":   kss.CurrentBlock.Header.LogCount,
			"merkle_root": kss.CurrentBlock.Header.MerkleRoot,
		}
		// 如果签名成功，也更新签名
		if signature != "" {
			updates["block_signature"] = signature
		}
		dbStore.DB.Model(&BlockHeaderModel{}).Where("block_id = ?", blockID).Updates(updates)
		// 同时持久化日志
		_ = persistLog(dbStore.DB, newLog, blockID)
	}

	return newLog
}

// 创建新区块（初始化区块头和区块体）
func (kss *KSSSystem) createNewBlock() {
	blockID := generateBlockID() // 生成19位唯一区块ID
	var prevBlockHash string     // 前一个区块头的哈希

	// 若为首个区块，前哈希设为固定值；否则从数据库获取最新区块的头哈希
	if dbStore != nil && dbStore.DB != nil {
		var count int64
		dbStore.DB.Model(&BlockHeaderModel{}).Count(&count)
		if count == 0 {
			prevBlockHash = "INIT-KSS-HASH" // 首个区块的前哈希固定值
		} else {
			// 从数据库获取最新的区块
			var latestBlock BlockHeaderModel
			dbStore.DB.Order("block_id desc").First(&latestBlock)
			prevBlockHash = calculateBlockHeaderHash(&BlockHeader{
				BlockID:        latestBlock.BlockID,
				PrevBlockHash:  latestBlock.PrevBlockHash,
				MerkleRoot:     latestBlock.MerkleRoot,
				BlockSignature: latestBlock.BlockSignature,
				LogCount:       latestBlock.LogCount,
			})
		}
	} else {
		// 如果数据库不可用，回退到内存方式
		if len(kss.Blocks) == 0 {
			prevBlockHash = "INIT-KSS-HASH" // 首个区块的前哈希固定值
		} else {
			var latestBlock *Block
			for _, block := range kss.Blocks {
				if latestBlock == nil || block.Header.BlockID > latestBlock.Header.BlockID {
					latestBlock = block
				}
			}
			prevBlockHash = calculateBlockHeaderHash(latestBlock.Header)
		}
	}

	// 初始化区块头（MerkleRoot初始为空，后续添加日志时更新）
	blockHeader := &BlockHeader{
		BlockID:        blockID,
		PrevBlockHash:  prevBlockHash,
		MerkleRoot:     "",
		BlockSignature: "", // 确保签名为空
		LogCount:       0,
	}

	// 初始化区块体（日志列表为空）
	blockBody := &BlockBody{
		BlockID: blockID,
		Logs:    []*Log{},
	}

	// 赋值给当前区块
	kss.CurrentBlock = &Block{
		Header: blockHeader,
		Body:   blockBody,
	}
	// 记录区块开始分钟
	kss.currentBlockMinute = time.Now().Unix() / 60
}

// 封块操作（对区块头签名，持久化存储区块）
func (kss *KSSSystem) finalizeBlock() error {
	// 1. 校验当前区块是否存在
	if kss.CurrentBlock == nil {
		return fmt.Errorf("无当前区块可封")
	}

	// 2. 确保Merkle根已计算（避免空区块）
	if kss.CurrentBlock.Header.MerkleRoot == "" && kss.CurrentBlock.Header.LogCount > 0 {
		kss.updateMerkleRoot()
	}

	// 3. 注意：不再在这里签名，因为每次添加日志时已经签名了
	// 确保区块有签名
	if kss.CurrentBlock.Header.BlockSignature == "" {
		return fmt.Errorf("区块头缺少签名")
	}

	// 4. 持久化存储区块
	blockID := kss.CurrentBlock.Header.BlockID
	kss.Blocks[blockID] = kss.CurrentBlock
	fmt.Printf("区块 %s 已封块，包含 %d 条日志\n", blockID, kss.CurrentBlock.Header.LogCount)

	return nil
}

// 对区块头进行签名（使用根密钥的RSA-PKCS1v15算法）
func (kss *KSSSystem) signBlockHeader(header *BlockHeader) (string, error) {
	// 序列化区块头（排除签名字段，避免循环依赖）
	headerCopy := *header
	headerCopy.BlockSignature = "" // 临时清空签名
	headerBytes, err := json.Marshal(headerCopy)
	if err != nil {
		return "", fmt.Errorf("区块头序列化失败：%v", err)
	}

	// 计算区块头哈希（SHA-256）
	headerHash := sha256.Sum256(headerBytes)

	// 用根密钥签名
	signatureBytes, err := rsa.SignPKCS1v15(
		r2.Reader,
		kss.RootKey,
		crypto.SHA256,
		headerHash[:],
	)
	if err != nil {
		return "", fmt.Errorf("RSA签名失败：%v", err)
	}

	// 返回16进制签名字符串
	return hex.EncodeToString(signatureBytes), nil
}

// 验证区块头签名（使用根密钥的公钥）
func (kss *KSSSystem) verifyBlockSignature(header *BlockHeader) bool {
	// 1. 校验签名是否为空
	if header.BlockSignature == "" {
		fmt.Printf("区块 %s 签名为空\n", header.BlockID)
		return false
	}

	// 2. 序列化区块头（排除签名字段）
	headerCopy := *header
	headerCopy.BlockSignature = ""
	headerBytes, err := json.Marshal(headerCopy)
	if err != nil {
		fmt.Printf("区块 %s 头序列化失败：%v\n", header.BlockID, err)
		return false
	}

	// 3. 解码签名字符串为字节数组
	signatureBytes, err := hex.DecodeString(header.BlockSignature)
	if err != nil {
		fmt.Printf("区块 %s 签名解码失败：%v\n", header.BlockID, err)
		return false
	}

	// 4. 计算区块头哈希并验证签名
	headerHash := sha256.Sum256(headerBytes)
	err = rsa.VerifyPKCS1v15(
		&kss.RootKey.PublicKey,
		crypto.SHA256,
		headerHash[:],
		signatureBytes,
	)
	if err != nil {
		fmt.Printf("区块 %s 签名验证失败：%v\n", header.BlockID, err)
		return false
	}

	return true
}

// 修改 VerifyBlock 方法，用于单独验证一个区块（从数据库读取）
func (kss *KSSSystem) VerifyBlock(blockID string) *BlockVerificationResult {
	result := &BlockVerificationResult{
		BlockID: blockID,
		Valid:   true,
	}

	// 优先从数据库查找区块
	var targetBlock *Block
	if dbStore != nil && dbStore.DB != nil {
		var header BlockHeaderModel
		if err := dbStore.DB.Where("block_id = ?", blockID).First(&header).Error; err == nil {
			// 从数据库读取日志
			var logs []LogModel
			dbStore.DB.Where("block_id = ?", blockID).Order("id asc").Find(&logs)

			// 转换为 Block 结构
			targetBlock = &Block{
				Header: &BlockHeader{
					BlockID:        header.BlockID,
					PrevBlockHash:  header.PrevBlockHash,
					MerkleRoot:     header.MerkleRoot,
					BlockSignature: header.BlockSignature,
					LogCount:       header.LogCount,
				},
				Body: &BlockBody{
					BlockID: header.BlockID,
					Logs:    []*Log{},
				},
			}
			for _, lm := range logs {
				targetBlock.Body.Logs = append(targetBlock.Body.Logs, &Log{
					LogID:       lm.LogID,
					Time:        lm.Time,
					Operator:    lm.Operator,
					KeyID:       lm.KeyID,
					Action:      lm.Action,
					Content:     lm.Content,
					PrevHash:    lm.PrevHash,
					CurrentHash: lm.CurrentHash,
					Valid:       lm.Valid,
				})
			}
		}
	}
	if targetBlock == nil {
		return result
	}

	// 验证区块内每个日志的哈希有效性
	for _, log := range targetBlock.Body.Logs {
		calculatedLogHash := log.GenerateHash()
		if calculatedLogHash != log.CurrentHash {
			result.TamperedLogs = append(result.TamperedLogs, log.LogID)
			result.Valid = false
		}
	}

	// 验证区块内部Merkle根
	var leafHashes []string
	for _, log := range targetBlock.Body.Logs {
		leafHashes = append(leafHashes, log.CurrentHash)
	}
	calculatedMerkleRoot := buildMerkleTree(leafHashes)
	result.MerkleValid = (calculatedMerkleRoot == targetBlock.Header.MerkleRoot)
	if !result.MerkleValid {
		result.Valid = false
	}

	// 验证区块签名
	result.SignatureValid = kss.verifyBlockSignature(targetBlock.Header)
	if !result.SignatureValid {
		result.Valid = false
	}

	return result
}

// 更新区块的Merkle根（基于当前区块内所有日志的哈希）
func (kss *KSSSystem) updateMerkleRoot() {
	// 若当前区块无日志，Merkle根设为空
	if kss.CurrentBlock == nil || len(kss.CurrentBlock.Body.Logs) == 0 {
		kss.CurrentBlock.Header.MerkleRoot = ""
		return
	}

	// 收集所有日志的CurrentHash作为Merkle树的叶子节点
	var leafHashes []string
	for _, log := range kss.CurrentBlock.Body.Logs {
		leafHashes = append(leafHashes, log.CurrentHash)
	}

	// 计算Merkle根并更新到区块头
	merkleRoot := buildMerkleTree(leafHashes)
	kss.CurrentBlock.Header.MerkleRoot = merkleRoot
}

// 构建Merkle树并返回根哈希（两两组合，递归计算）
func buildMerkleTree(leafHashes []string) string {
	// 1. 若叶子节点为空，返回空哈希
	if len(leafHashes) == 0 {
		return ""
	}

	// 2. 若只有一个叶子节点，直接返回该节点哈希
	if len(leafHashes) == 1 {
		return leafHashes[0]
	}

	// 3. 两两组合计算父节点哈希（奇数个节点时，最后一个与自身组合）
	var parentHashes []string
	for i := 0; i < len(leafHashes); i += 2 {
		// 取当前节点和下一个节点（若存在）
		currentHash := leafHashes[i]
		nextHash := currentHash // 奇数个节点时，下一个节点为自身
		if i+1 < len(leafHashes) {
			nextHash = leafHashes[i+1]
		}

		// 计算父节点哈希（拼接两个子节点哈希后SHA-256）
		parentHash := calculateHash(currentHash + nextHash)
		parentHashes = append(parentHashes, parentHash)
	}

	// 4. 递归计算上一层，直到得到根哈希
	return buildMerkleTree(parentHashes)
}

// 生成Merkle树中目标日志的哈希路径（用于单条日志验证）
func getMerklePath(leafHashes []string, targetIndex int) []string {
	var path []string          // 存储哈希路径（兄弟节点哈希）
	currentLevel := leafHashes // 当前层的节点哈希
	currentIdx := targetIndex  // 当前目标节点的索引

	// 递归向上计算，直到根节点
	for len(currentLevel) > 1 {
		var nextLevel []string // 下一层的父节点哈希

		// 记录当前节点的兄弟节点哈希
		if currentIdx%2 == 0 {
			// 偶数索引：兄弟节点在右侧
			if currentIdx+1 < len(currentLevel) {
				path = append(path, currentLevel[currentIdx+1])
			} else {
				// 奇数个节点：兄弟节点为自身
				path = append(path, currentLevel[currentIdx])
			}
		} else {
			// 奇数索引：兄弟节点在左侧
			path = append(path, currentLevel[currentIdx-1])
		}

		// 计算下一层父节点哈希
		for i := 0; i < len(currentLevel); i += 2 {
			currentHash := currentLevel[i]
			nextHash := currentHash
			if i+1 < len(currentLevel) {
				nextHash = currentLevel[i+1]
			}
			parentHash := calculateHash(currentHash + nextHash)
			nextLevel = append(nextLevel, parentHash)
		}

		// 更新当前层和目标索引（进入上一层）
		currentLevel = nextLevel
		currentIdx = currentIdx / 2
	}

	return path
}

// 验证单条日志的完整性（日志内容、链式关联、Merkle路径、区块签名）
func (kss *KSSSystem) VerifyLog(logID, blockID string) bool {
	// 1. 校验日志ID格式（必须至少16位：LOG+BLK+至少7位时间戳+3位序号）
	if len(logID) < 16 || !strings.HasPrefix(logID, "LOG") {
		fmt.Printf("日志ID格式错误：%s（长度%d位）\n", logID, len(logID))
		return false
	}
	fmt.Printf("正在验证日志 %s...\n", logID)

	// 2. 如果没有提供blockID，则从日志ID中提取区块ID
	if blockID == "" {
		// 日志ID格式：LOG + BlockID + 3位序号
		// 例如：LOGBLK1760340578001，其中BLK1760340578是区块ID，001是序号
		if len(logID) >= 7 { // LOG(3) + 至少1位 + 3位序号
			blockID = logID[3 : len(logID)-3]
		}
	}

	// 3. 查找目标区块
	var targetBlock *Block

	// 优先从数据库查找区块
	if dbStore != nil && dbStore.DB != nil {
		var header BlockHeaderModel
		if err := dbStore.DB.Where("block_id = ?", blockID).First(&header).Error; err == nil {
			fmt.Printf("从数据库中读取区块 %s...\n", blockID)
			// 从数据库读取日志
			var logs []LogModel
			dbStore.DB.Where("block_id = ?", blockID).Order("id asc").Find(&logs)

			// 转换为 Block 结构
			targetBlock = &Block{
				Header: &BlockHeader{
					BlockID:        header.BlockID,
					PrevBlockHash:  header.PrevBlockHash,
					MerkleRoot:     header.MerkleRoot,
					BlockSignature: header.BlockSignature,
					LogCount:       header.LogCount,
				},
				Body: &BlockBody{
					BlockID: header.BlockID,
					Logs:    []*Log{},
				},
			}
			for _, lm := range logs {
				targetBlock.Body.Logs = append(targetBlock.Body.Logs, &Log{
					LogID:       lm.LogID,
					Time:        lm.Time,
					Operator:    lm.Operator,
					KeyID:       lm.KeyID,
					Action:      lm.Action,
					Content:     lm.Content,
					PrevHash:    lm.PrevHash,
					CurrentHash: lm.CurrentHash,
					Valid:       lm.Valid,
				})
			}
		}
	}
	log.Println("正在验证区块 ...", targetBlock)

	// 4. 查找目标日志
	var targetLog *Log
	for _, log := range targetBlock.Body.Logs {
		if log.LogID == logID {
			targetLog = log
			break
		}
	}
	if targetLog == nil {
		fmt.Printf("日志 %s 不在区块 %s 中\n", logID, blockID)
		return false
	}

	// 5. 验证日志自身哈希（内容未篡改）
	calculatedLogHash := targetLog.GenerateHash()
	if calculatedLogHash != targetLog.CurrentHash {
		fmt.Printf("日志 %s 内容被篡改：\n- 计算哈希：%s\n- 存储哈希：%s\n",
			logID, calculatedLogHash, targetLog.CurrentHash)
		return false
	}

	// 6. 验证与前一条日志的链式关联（非第一条日志）
	if targetLog.PrevHash != "" {
		var prevLog *Log
		for _, log := range targetBlock.Body.Logs {
			if log.CurrentHash == targetLog.PrevHash {
				prevLog = log
				break
			}
		}
		if prevLog == nil {
			fmt.Printf("日志 %s 的前序日志哈希无效：%s\n", logID, targetLog.PrevHash)
			return false
		}
	}

	// 7. 验证Merkle路径（日志属于当前区块且未被篡改）
	var leafHashes []string
	var targetLogIndex int
	for idx, log := range targetBlock.Body.Logs {
		leafHashes = append(leafHashes, log.CurrentHash)
		if log.LogID == logID {
			targetLogIndex = idx
		}
	}
	// 生成哈希路径并重新计算Merkle根
	merklePath := getMerklePath(leafHashes, targetLogIndex)
	currentHash := targetLog.CurrentHash
	for _, siblingHash := range merklePath {
		if targetLogIndex%2 == 0 {
			// 偶数索引：当前哈希在左，兄弟哈希在右
			currentHash = calculateHash(currentHash + siblingHash)
		} else {
			// 奇数索引：当前哈希在右，兄弟哈希在左
			currentHash = calculateHash(siblingHash + currentHash)
		}
		targetLogIndex = targetLogIndex / 2 // 更新索引到上一层
	}
	// 对比计算根与区块存储的Merkle根
	if currentHash != targetBlock.Header.MerkleRoot {
		fmt.Printf("日志 %s 的Merkle路径验证失败：\n- 计算根：%s\n- 区块根：%s\n",
			logID, currentHash, targetBlock.Header.MerkleRoot)
		return false
	}

	// 所有验证通过
	fmt.Printf("日志 %s 验证通过（所属区块：%s）\n", logID, blockID)
	return true
}

// 验证区块链完整性（修复版：从数据库读取并增加日志哈希验证）
func (kss *KSSSystem) VerifyBlockchain() bool {
	// 1. 从数据库收集所有已封块
	var blocks []*Block
	if dbStore != nil && dbStore.DB != nil {
		var headers []BlockHeaderModel
		dbStore.DB.Where("block_signature != ?", "").Order("block_id asc").Find(&headers)

		for _, header := range headers {
			var logs []LogModel
			dbStore.DB.Where("block_id = ?", header.BlockID).Order("id asc").Find(&logs)

			block := &Block{
				Header: &BlockHeader{
					BlockID:        header.BlockID,
					PrevBlockHash:  header.PrevBlockHash,
					MerkleRoot:     header.MerkleRoot,
					BlockSignature: header.BlockSignature,
					LogCount:       header.LogCount,
				},
				Body: &BlockBody{
					BlockID: header.BlockID,
					Logs:    []*Log{},
				},
			}
			for _, lm := range logs {
				block.Body.Logs = append(block.Body.Logs, &Log{
					LogID:       lm.LogID,
					Time:        lm.Time,
					Operator:    lm.Operator,
					KeyID:       lm.KeyID,
					Action:      lm.Action,
					Content:     lm.Content,
					PrevHash:    lm.PrevHash,
					CurrentHash: lm.CurrentHash,
					Valid:       lm.Valid,
				})
			}
			blocks = append(blocks, block)
		}
	}

	// 校验是否有已封块
	if len(blocks) == 0 {
		fmt.Println("无已封块，区块链为空")
		return true
	}

	// 3. 逐个验证区块
	for i := 0; i < len(blocks); i++ {
		currentBlock := blocks[i]
		blockID := currentBlock.Header.BlockID

		// 【新增】验证区块内每个日志的哈希有效性
		for _, log := range currentBlock.Body.Logs {
			calculatedLogHash := log.GenerateHash()
			if calculatedLogHash != log.CurrentHash {
				fmt.Printf("区块链验证失败：区块 %s 中日志 %s 内容被篡改\n",
					blockID, log.LogID)
				fmt.Printf("- 计算哈希：%s\n- 存储哈希：%s\n",
					calculatedLogHash, log.CurrentHash)
				return false
			}
		}

		// 验证区块内部Merkle根
		var leafHashes []string
		for _, log := range currentBlock.Body.Logs {
			leafHashes = append(leafHashes, log.CurrentHash)
		}
		calculatedMerkleRoot := buildMerkleTree(leafHashes)
		if calculatedMerkleRoot != currentBlock.Header.MerkleRoot {
			fmt.Printf("区块链验证失败：区块 %s 内部日志被篡改\n", blockID)
			fmt.Printf("- 计算Merkle根：%s\n- 存储Merkle根：%s\n",
				calculatedMerkleRoot, currentBlock.Header.MerkleRoot)
			return false
		}

		// 验证区块签名
		if !kss.verifyBlockSignature(currentBlock.Header) {
			fmt.Printf("区块链验证失败：区块 %s 签名无效\n", blockID)
			return false
		}

		// 验证区块间链式关联（非首个区块）
		if i > 0 {
			prevBlock := blocks[i-1]
			prevBlockHeaderHash := calculateBlockHeaderHash(prevBlock.Header)
			if currentBlock.Header.PrevBlockHash != prevBlockHeaderHash {
				fmt.Printf("区块链验证失败：区块 %s 与前区块 %s 关联断裂\n",
					blockID, prevBlock.Header.BlockID)
				fmt.Printf("- 当前区块存储的前哈希：%s\n- 前区块头实际哈希：%s\n",
					currentBlock.Header.PrevBlockHash, prevBlockHeaderHash)
				return false
			}
		}
	}

	// 所有区块验证通过
	fmt.Println("区块链完整性验证通过")
	return true
}

// 计算区块头的哈希（排除签名字段，用于链式关联）
func calculateBlockHeaderHash(header *BlockHeader) string {
	// 拼接区块头关键字段（BlockID、PrevBlockHash、MerkleRoot、LogCount）
	hashSource := fmt.Sprintf(
		"BlockID=%s&PrevBlockHash=%s&MerkleRoot=%s&LogCount=%d",
		header.BlockID, header.PrevBlockHash, header.MerkleRoot, header.LogCount,
	)
	return calculateHash(hashSource)
}

// 保存 RSA 私钥到文件
func saveRSAPrivateKey(filename string, key *rsa.PrivateKey) error {
	// 将私钥编码为 PKCS#1 格式
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)

	// 创建 PEM 块
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// 写入文件
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建密钥文件失败：%v", err)
	}
	defer file.Close()

	if err := pem.Encode(file, privateKeyBlock); err != nil {
		return fmt.Errorf("编码密钥失败：%v", err)
	}

	return nil
}

// 从文件加载 RSA 私钥
func loadRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
	// 读取文件
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取密钥文件失败：%v", err)
	}

	// 解码 PEM 块
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("无效的密钥文件格式")
	}

	// 解析私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析密钥失败：%v", err)
	}

	return privateKey, nil
}

// 获取或生成 RSA 密钥
func getOrCreateRSAKey(filename string) (*rsa.PrivateKey, error) {
	// 尝试从文件加载
	key, err := loadRSAPrivateKey(filename)
	if err == nil {
		fmt.Printf("从文件 %s 加载根密钥成功\n", filename)
		return key, nil
	}

	// 文件不存在或加载失败，生成新密钥
	fmt.Printf("密钥文件不存在，生成新的根密钥...\n")
	key, err = rsa.GenerateKey(r2.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成密钥失败：%v", err)
	}

	// 保存到文件
	if err := saveRSAPrivateKey(filename, key); err != nil {
		return nil, fmt.Errorf("保存密钥失败：%v", err)
	}

	fmt.Printf("根密钥已保存到文件 %s\n", filename)
	return key, nil
}

// 持久化辅助方法
func persistLog(db *gorm.DB, l *Log, blockID string) error {
	if db == nil || l == nil {
		return nil
	}
	m := &LogModel{
		LogID:       l.LogID,
		Time:        l.Time,
		Operator:    l.Operator,
		KeyID:       l.KeyID,
		Action:      l.Action,
		Content:     l.Content,
		PrevHash:    l.PrevHash,
		CurrentHash: l.CurrentHash,
		Valid:       l.Valid,
		BlockID:     blockID,
	}
	return db.Where("log_id = ?", l.LogID).Assign(m).FirstOrCreate(m).Error
}
func persistBlock(db *gorm.DB, b *Block) error {
	if db == nil || b == nil || b.Header == nil {
		return nil
	}
	bh := &BlockHeaderModel{
		BlockID:        b.Header.BlockID,
		PrevBlockHash:  b.Header.PrevBlockHash,
		MerkleRoot:     b.Header.MerkleRoot,
		BlockSignature: b.Header.BlockSignature, // 确保保存签名
		LogCount:       b.Header.LogCount,
		IsSealed:       b.Header.BlockSignature != "", // 如果有签名则认为已封块
	}
	if err := db.Where("block_id = ?", bh.BlockID).Assign(bh).FirstOrCreate(bh).Error; err != nil {
		return err
	}
	// 同步区块内日志（冗余保存，便于通过 DB 查询）
	for _, l := range b.Body.Logs {
		if err := persistLog(db, l, b.Header.BlockID); err != nil {
			return err
		}
	}
	return nil
}

// Web 服务实现
var (
	globalKSS *KSSSystem
	stateMu   sync.Mutex
	dbStore   *Database
)

type createLogRequest struct {
	Operator string `json:"operator"`
	KeyID    string `json:"keyId"`
	Action   string `json:"action"`
	Content  string `json:"content"`
}

func main() {
	// 初始化核心对象 - 从文件加载或生成根密钥
	rootKey, err := getOrCreateRSAKey("root_key.pem")
	if err != nil {
		log.Fatalf("初始化根密钥失败：%v", err)
	}
	globalKSS = NewKSSSystem(rootKey)

	// 初始化数据库（SQLite 文件：kss.db）
	ds, err := InitDatabase("kss.db")
	if err != nil {
		log.Fatalf("初始化数据库失败：%v", err)
	}
	dbStore = ds
	// 每分钟自动封块（每分钟的第0秒执行）
	go func() {
		for {
			now := time.Now()
			// 计算到下一分钟整点的等待时间
			nextMinute := now.Truncate(time.Minute).Add(time.Minute)
			time.Sleep(time.Until(nextMinute))

			stateMu.Lock()
			// 只有当前区块存在且有日志时才处理
			if globalKSS != nil && globalKSS.CurrentBlock != nil && globalKSS.CurrentBlock.Header.LogCount > 0 {
				// 检查当前区块是否应该封块
				currentMinuteTimestamp := time.Now().Unix() / 60 * 60
				blockMinuteTimestamp := extractTimestampFromBlockID(globalKSS.CurrentBlock.Header.BlockID)

				if currentMinuteTimestamp > blockMinuteTimestamp {
					// 有日志且已过区块时间，才封块
					if err := globalKSS.finalizeBlock(); err == nil {
						if dbStore != nil && dbStore.DB != nil {
							_ = persistBlock(dbStore.DB, globalKSS.Blocks[globalKSS.CurrentBlock.Header.BlockID])
							// 更新数据库中的区块状态为已封块
							dbStore.DB.Model(&BlockHeaderModel{}).Where("block_id = ?", globalKSS.CurrentBlock.Header.BlockID).Updates(map[string]interface{}{
								"is_sealed":       true,
								"block_signature": globalKSS.CurrentBlock.Header.BlockSignature, // 确保签名也被更新
							})
						}
						fmt.Printf("[自动封块] %s 已封块\n", globalKSS.CurrentBlock.Header.BlockID)
						// 清空当前区块
						globalKSS.CurrentBlock = nil
						globalKSS.currentLogCount = 0
					}
				}
			}
			stateMu.Unlock()
		}
	}()
	// Gin 服务器
	r := gin.Default()

	// 静态页面与资源
	r.Static("/static", "./static")
	r.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})

	// 下载数据库文件（便于查看/备份）
	r.GET("/api/dbfile", func(c *gin.Context) {
		c.Header("Content-Disposition", "attachment; filename=kss.db")
		c.File("kss.db")
	})

	api := r.Group("/api")
	{
		api.POST("/logs", func(c *gin.Context) {
			var req createLogRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			if req.Operator == "" || req.KeyID == "" || req.Action == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "operator/keyId/action 不能为空"})
				return
			}
			stateMu.Lock()
			logItem := globalKSS.CreateLog(req.Operator, req.KeyID, req.Action, req.Content)
			// 持久化日志
			_ = persistLog(dbStore.DB, logItem, globalKSS.CurrentBlock.Header.BlockID)
			stateMu.Unlock()
			c.JSON(http.StatusOK, logItem)
		})
		api.POST("/finalize", func(c *gin.Context) {
			stateMu.Lock()
			var err error
			// 只有当前区块存在且有日志时才允许手动封块
			if globalKSS.CurrentBlock != nil && globalKSS.CurrentBlock.Header.LogCount > 0 {
				err = globalKSS.finalizeBlock()
				if err == nil {
					// 持久化区块头与区块体
					_ = persistBlock(dbStore.DB, globalKSS.Blocks[globalKSS.CurrentBlock.Header.BlockID])
					// 更新数据库中的区块状态为已封块
					if dbStore != nil && dbStore.DB != nil {
						dbStore.DB.Model(&BlockHeaderModel{}).Where("block_id = ?", globalKSS.CurrentBlock.Header.BlockID).Updates(map[string]interface{}{
							"is_sealed":       true,
							"block_signature": globalKSS.CurrentBlock.Header.BlockSignature, // 确保签名也被更新
						})
					}
					// 清空当前区块
					globalKSS.CurrentBlock = nil
					globalKSS.currentLogCount = 0
				}
			} else {
				if globalKSS.CurrentBlock == nil {
					err = fmt.Errorf("当前无区块可封")
				} else {
					err = fmt.Errorf("当前区块无日志，无需封块")
				}
			}
			stateMu.Unlock()
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "封块完成"})
		})

		api.GET("/blocks/:id", func(c *gin.Context) {
			id := c.Param("id")
			stateMu.Lock()
			defer stateMu.Unlock()

			// 优先从数据库读取
			if dbStore != nil && dbStore.DB != nil {
				var h BlockHeaderModel
				if err := dbStore.DB.Where("block_id = ?", id).First(&h).Error; err == nil {
					var logs []LogModel
					_ = dbStore.DB.Where("block_id = ?", id).Order("id asc").Find(&logs).Error

					// 进行验证
					verificationResult := globalKSS.VerifyBlock(id)

					var logsOut []gin.H
					tamperedLogMap := make(map[string]bool)
					for _, logID := range verificationResult.TamperedLogs {
						tamperedLogMap[logID] = true
					}

					for _, lm := range logs {
						calc := (&Log{LogID: lm.LogID, Time: lm.Time, Operator: lm.Operator, KeyID: lm.KeyID, Action: lm.Action, Content: lm.Content}).GenerateHash()
						logsOut = append(logsOut, gin.H{
							"LogID":            lm.LogID,
							"Operator":         lm.Operator,
							"KeyID":            lm.KeyID,
							"Action":           lm.Action,
							"Time":             lm.Time,
							"CurrentHash":      lm.CurrentHash,
							"tampered":         tamperedLogMap[lm.LogID],
							"recalculatedHash": calc,
						})
					}

					c.JSON(http.StatusOK, gin.H{
						"Header": gin.H{
							"BlockID":       h.BlockID,
							"PrevBlockHash": h.PrevBlockHash,
							"MerkleRoot":    h.MerkleRoot,
							"LogCount":      h.LogCount,
						},
						"Logs":         logsOut,
						"Verification": verificationResult,
					})
					return
				}
			}

			// 若数据库无，检查是否为当前未封块
			if globalKSS.CurrentBlock != nil && globalKSS.CurrentBlock.Header.BlockID == id {
				verificationResult := &BlockVerificationResult{
					BlockID:        id,
					Valid:          true,
					SignatureValid: false,
					MerkleValid:    true,
				}

				var logsOut []gin.H
				for _, l := range globalKSS.CurrentBlock.Body.Logs {
					calc := l.GenerateHash()
					logsOut = append(logsOut, gin.H{
						"LogID":            l.LogID,
						"Operator":         l.Operator,
						"KeyID":            l.KeyID,
						"Action":           l.Action,
						"Time":             l.Time,
						"CurrentHash":      l.CurrentHash,
						"tampered":         calc != l.CurrentHash,
						"recalculatedHash": calc,
					})
				}

				bh := globalKSS.CurrentBlock.Header
				resp := gin.H{
					"Header": gin.H{
						"BlockID":       bh.BlockID,
						"PrevBlockHash": bh.PrevBlockHash,
						"MerkleRoot":    bh.MerkleRoot,
						"LogCount":      bh.LogCount,
					},
					"Logs":         logsOut,
					"Verification": verificationResult,
				}
				c.JSON(http.StatusOK, resp)
				return
			}

			c.JSON(http.StatusNotFound, gin.H{"error": "区块不存在"})
		})
		api.GET("/blocks", func(c *gin.Context) {
			stateMu.Lock()
			defer stateMu.Unlock()

			// 整体区块链验证
			blockchainValid := globalKSS.VerifyBlockchain()

			// 分页与时间筛选
			page := 1
			pageSize := 10
			if v := c.Query("page"); v != "" {
				fmt.Sscanf(v, "%d", &page)
			}
			if v := c.Query("pageSize"); v != "" {
				fmt.Sscanf(v, "%d", &pageSize)
			}
			if page <= 0 {
				page = 1
			}
			if pageSize <= 0 || pageSize > 100 {
				pageSize = 10
			}
			start := c.Query("start") // 毫秒时间戳
			end := c.Query("end")

			// 完全从数据库读取区块头
			var list []BlockHeaderModel
			var total int64
			if dbStore != nil && dbStore.DB != nil {
				dbq := dbStore.DB.Model(&BlockHeaderModel{})
				if start != "" {
					var ms int64
					fmt.Sscanf(start, "%d", &ms)
					dbq = dbq.Where("created_at >= ?", time.UnixMilli(ms))
				}
				if end != "" {
					var ms int64
					fmt.Sscanf(end, "%d", &ms)
					dbq = dbq.Where("created_at <= ?", time.UnixMilli(ms))
				}
				dbq.Count(&total)
				dbq.Order("block_id asc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&list)

				// 只有当当前区块存在且有日志时才附加到列表
				if globalKSS.CurrentBlock != nil && globalKSS.CurrentBlock.Header.LogCount > 0 {
					exists := false
					for _, h := range list {
						if h.BlockID == globalKSS.CurrentBlock.Header.BlockID {
							exists = true
							// 更新现有记录
							if dbStore != nil && dbStore.DB != nil {
								dbStore.DB.Model(&BlockHeaderModel{}).Where("block_id = ?", h.BlockID).Updates(map[string]interface{}{
									"log_count":   globalKSS.CurrentBlock.Header.LogCount,
									"merkle_root": globalKSS.CurrentBlock.Header.MerkleRoot,
								})
							}
							break
						}
					}
					if !exists {
						currentBlockModel := BlockHeaderModel{
							BlockID:        globalKSS.CurrentBlock.Header.BlockID,
							PrevBlockHash:  globalKSS.CurrentBlock.Header.PrevBlockHash,
							MerkleRoot:     globalKSS.CurrentBlock.Header.MerkleRoot,
							BlockSignature: globalKSS.CurrentBlock.Header.BlockSignature,
							LogCount:       globalKSS.CurrentBlock.Header.LogCount,
							IsSealed:       false, // 当前区块未被封块
						}
						list = append(list, currentBlockModel)
						total++
					}
				}

				// 为每个区块生成验证结果
				blockVerifications := make(map[string]*BlockVerificationResult)
				for _, blockHeader := range list {
					blockVerifications[blockHeader.BlockID] = globalKSS.VerifyBlock(blockHeader.BlockID)
				}

				// 为每个区块添加时间信息
				var enhancedList []gin.H
				for _, h := range list {
					timestamp := extractTimestampFromBlockID(h.BlockID)
					enhancedList = append(enhancedList, gin.H{
						"BlockID":        h.BlockID,
						"PrevBlockHash":  h.PrevBlockHash,
						"MerkleRoot":     h.MerkleRoot,
						"BlockSignature": h.BlockSignature,
						"LogCount":       h.LogCount,
						"IsSealed":       h.IsSealed,
						"CreatedAt":      h.CreatedAt,
						"Timestamp":      timestamp,
						"DateTime":       time.Unix(timestamp, 0).Format("2006-01-02 15:04:05"),
					})
				}

				c.JSON(http.StatusOK, gin.H{
					"blockchainValid":    blockchainValid,
					"total":              total,
					"list":               enhancedList,
					"blockVerifications": blockVerifications,
				})
				return
			}

			// 数据库不可用时返回错误
			c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库不可用"})
		})

		//api.GET("/logs/:logId/verify", func(c *gin.Context) {
		//	logID := c.Param("logId")
		//	stateMu.Lock()
		//	ok := globalKSS.VerifyLog(logID)
		//	stateMu.Unlock()
		//	c.JSON(http.StatusOK, gin.H{"logId": logID, "valid": ok})
		//})

		api.GET("/verify", func(c *gin.Context) {
			stateMu.Lock()
			ok := globalKSS.VerifyBlockchain()
			stateMu.Unlock()
			c.JSON(http.StatusOK, gin.H{"blockchainValid": ok})
		})

		api.GET("/state", func(c *gin.Context) {
			stateMu.Lock()
			defer stateMu.Unlock()
			resp := gin.H{
				"currentBlockId":    "",
				"currentLogCount":   0,
				"randomBlockSize":   globalKSS.randomBlockSize,
				"sealedBlocksCount": len(globalKSS.Blocks),
			}
			if globalKSS.CurrentBlock != nil {
				resp["currentBlockId"] = globalKSS.CurrentBlock.Header.BlockID
				resp["currentLogCount"] = globalKSS.CurrentBlock.Header.LogCount
			}
			c.JSON(http.StatusOK, resp)
		})
		// 在 /api/logs 接口的处理函数中，修改日志验证逻辑
		api.GET("/logs", func(c *gin.Context) {
			stateMu.Lock()
			defer stateMu.Unlock()
			page := 1
			pageSize := 10
			if v := c.Query("page"); v != "" {
				fmt.Sscanf(v, "%d", &page)
			}
			if v := c.Query("pageSize"); v != "" {
				fmt.Sscanf(v, "%d", &pageSize)
			}
			if page <= 0 {
				page = 1
			}
			if pageSize <= 0 || pageSize > 100 {
				pageSize = 10
			}
			operator := c.Query("operator")
			keyId := c.Query("keyId")
			action := c.Query("action")
			start := c.Query("start") // 毫秒
			end := c.Query("end")
			var total int64
			var list []LogModel
			if dbStore != nil && dbStore.DB != nil {
				dbq := dbStore.DB.Model(&LogModel{})
				if operator != "" {
					dbq = dbq.Where("operator = ?", operator)
				}
				if keyId != "" {
					dbq = dbq.Where("key_id = ?", keyId)
				}
				if action != "" {
					dbq = dbq.Where("action = ?", action)
				}
				if start != "" {
					var ms int64
					fmt.Sscanf(start, "%d", &ms)
					dbq = dbq.Where("time >= ?", ms)
				}
				if end != "" {
					var ms int64
					fmt.Sscanf(end, "%d", &ms)
					dbq = dbq.Where("time <= ?", ms)
				}
				dbq.Count(&total)
				dbq.Order("id asc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&list)
			}
			// 先构造输出并附加完整验证结果
			var out []gin.H
			for _, lm := range list {
				verified := true

				// 1. 简单哈希验证（快速检测内容篡改）
				calc := (&Log{LogID: lm.LogID, Time: lm.Time, Operator: lm.Operator, KeyID: lm.KeyID, Action: lm.Action, Content: lm.Content}).GenerateHash()
				hashTampered := calc != lm.CurrentHash
				if hashTampered {
					verified = false
				}

				// 2. 完整区块链验证（验证链式关联、Merkle路径、区块签名）
				if len(lm.LogID) >= 16 && strings.HasPrefix(lm.LogID, "LOG") && !hashTampered {
					fmt.Println("正在验证。。", lm.LogID)

					verified = globalKSS.VerifyLog(lm.LogID, lm.BlockID)
				}

				out = append(out, gin.H{
					"LogID":       lm.LogID,
					"Operator":    lm.Operator,
					"KeyID":       lm.KeyID,
					"Action":      lm.Action,
					"Time":        lm.Time,
					"BlockID":     lm.BlockID,
					"CurrentHash": lm.CurrentHash,
					"tampered":    hashTampered, // 内容是否被篡改
					"verified":    verified,     // 完整区块链验证结果
				})
			}
			// 若 DB 无数据或未启用 DB，则回退到内存聚合，确保创建后可见
			//if total == 0 && len(list) == 0 {
			//	var inMem []*Log
			//	// 只有当当前区块存在时才添加其日志
			//	if globalKSS.CurrentBlock != nil {
			//		inMem = append(inMem, globalKSS.CurrentBlock.Body.Logs...)
			//	}
			//	for _, b := range globalKSS.Blocks {
			//		inMem = append(inMem, b.Body.Logs...)
			//	}
			//	var filtered []*Log
			//	for _, l := range inMem {
			//		if operator != "" && l.Operator != operator {
			//			continue
			//		}
			//		if keyId != "" && l.KeyID != keyId {
			//			continue
			//		}
			//		if action != "" && l.Action != action {
			//			continue
			//		}
			//		if start != "" {
			//			var ms int64
			//			fmt.Sscanf(start, "%d", &ms)
			//			if l.Time < ms {
			//				continue
			//			}
			//		}
			//		if end != "" {
			//			var ms int64
			//			fmt.Sscanf(end, "%d", &ms)
			//			if l.Time > ms {
			//				continue
			//			}
			//		}
			//		filtered = append(filtered, l)
			//	}
			//	total = int64(len(filtered))
			//	startIdx := (page - 1) * pageSize
			//	endIdx := startIdx + pageSize
			//	if startIdx > len(filtered) {
			//		startIdx = len(filtered)
			//	}
			//	if endIdx > len(filtered) {
			//		endIdx = len(filtered)
			//	}
			//	for _, l := range filtered[startIdx:endIdx] {
			//		// 1. 简单哈希验证
			//		calc := l.GenerateHash()
			//		hashTampered := (calc != l.CurrentHash)
			//
			//		// 2. 完整区块链验证
			//		verified := true
			//		if len(l.LogID) >= 16 && strings.HasPrefix(l.LogID, "LOG") && !hashTampered {
			//			// 从日志ID中提取区块ID进行验证
			//			if len(l.LogID) > 6 {
			//				blockID := l.LogID[3 : len(l.LogID)-3]
			//				verified = globalKSS.VerifyLog(l.LogID, blockID)
			//			}
			//		}
			//
			//		out = append(out, gin.H{
			//			"LogID":       l.LogID,
			//			"Operator":    l.Operator,
			//			"KeyID":       l.KeyID,
			//			"Action":      l.Action,
			//			"Time":        l.Time,
			//			"BlockID":     "", // 内存中的未封块日志暂时没有BlockID
			//			"CurrentHash": l.CurrentHash,
			//			"tampered":    hashTampered,
			//			"verified":    verified,
			//		})
			//	}
			//}
			c.JSON(http.StatusOK, gin.H{"total": total, "list": out})
		})
	}

	// 监听端口
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("服务启动失败：%v", err)
	}
}
