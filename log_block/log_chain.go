package log_block

import (
	"crypto"
	r2 "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andang-secure/log-block-encrypt/data"
	"github.com/andang-secure/log-block-encrypt/global"
	"github.com/andang-secure/log-block-encrypt/model"
	"github.com/andang-secure/log-block-encrypt/utils"
	"gorm.io/gorm"
	"log"
	"strconv"
	"time"
)

type LogChainConf struct {
	RootKey              *rsa.PrivateKey
	DB                   *gorm.DB
	BlockHeaderTableName string
	BlockLogTableName    string
}

func NewLogChain(conf *LogChainConf) (*LogChain, error) {
	// 校验配置必填项
	if conf.DB == nil {
		return nil, errors.New("数据库连接未初始化")
	}
	if conf.BlockLogTableName == "" {
		return nil, errors.New("日志表名未设置")
	}
	if conf.BlockHeaderTableName == "" {
		return nil, errors.New("区块表名未设置")
	}
	if conf.RootKey == nil {
		return nil, errors.New("根密钥未初始化")
	}
	global.DB = conf.DB
	global.BlockLogTableName = conf.BlockLogTableName
	global.BlockHeaderTableName = conf.BlockHeaderTableName

	// 2. 创建LogChain实例
	// 2. 创建LogChain实例
	lc := &LogChain{
		rootKey:              conf.RootKey,
		blockHeaderModelImpl: &model.BlockHeaderModel{},
		blockLogModelImpl:    &model.BlockLogModel{},
	}
	lc.startAutoSealScheduler()
	return lc, nil
}

// LogChain 日志链
type LogChain struct {
	rootKey              *rsa.PrivateKey
	blockHeaderModelImpl model.BlockHeaderModelImpl
	blockLogModelImpl    model.BlockLogModelImpl
}

// startAutoSealScheduler 启动自动封块调度器，在每天凌晨 00:00 执行
func (lc *LogChain) startAutoSealScheduler() {
	go func() {
		for {
			// 计算到下一个凌晨 00:00 的时间
			now := time.Now()
			nextMidnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, 1)
			durationUntilNextMidnight := time.Until(nextMidnight)

			log.Printf("下次自动封块将在 %s 执行\n", nextMidnight.Format("2006-01-02 15:04:05"))

			// 等待到下一个凌晨 00:00
			time.Sleep(durationUntilNextMidnight)
			// 执行自动封块并处理错误
			if err := lc.AutoSealBlocks(); err != nil {
				log.Printf("自动封块执行失败: %v", err)
			}
		}
	}()
}

// AutoSealBlocks 自动封块方法
func (lc *LogChain) AutoSealBlocks() error {

	// 修复参数传递：传递指针获取未封块列表
	var unsealedBlocks []model.BlockHeaderModel
	if err := lc.blockHeaderModelImpl.GetNotSealedAll(&unsealedBlocks); err != nil {
		return fmt.Errorf("查询未封块失败: %w", err)
	}

	// 获取当前日期的时间戳（对齐到天）
	todayTimestamp := utils.GetTodayTimestamp()

	for _, blockHeader := range unsealedBlocks {
		// 从区块ID中提取时间戳
		blockIdToInt, err := utils.StrToInt(blockHeader.BlockID)
		if err != nil {
			log.Println("区块ID转换失败:", err)
			continue
		}

		// 如果区块的时间戳早于今天，且区块内有日志，则封块
		if blockIdToInt < todayTimestamp && blockHeader.LogCount > 0 {
			// 更新数据库中的区块状态为已封块
			if err := lc.finalizeBlock(&blockHeader); err != nil {
				log.Printf("更新区块 %v 状态失败: %v\n", blockHeader.BlockID, err)
				continue
			}
			log.Printf("[自动封块] 区块 %v 已封块（按天封块）\n\n", blockHeader.BlockID)
		}
	}
	return nil
}

// 封块操作（对区块头签名，持久化存储区块）
func (lc *LogChain) finalizeBlock(bh *model.BlockHeaderModel) error {

	// 2. 确保Merkle根已计算（避免空区块）
	if bh.MerkleRoot == "" && bh.LogCount > 0 {
		lc.updateMerkleRoot(bh)
		if bh.MerkleRoot == "" {
			return errors.New("merkle根计算失败，无法封块")
		}
	}
	// 对区块头进行签名
	signature, err := lc.SignBlockHeader(bh)
	if err != nil {
		return fmt.Errorf("区块 %s 签名失败: %v", bh.BlockID, err)
	}
	bh.BlockSignature = signature

	// 4. 持久化存储区块
	err = lc.blockHeaderModelImpl.Update(bh.BlockID, signature)
	if err != nil {
		return fmt.Errorf("区块 %s 持久化失败: %v", bh.BlockID, err)
	}
	log.Printf("区块[%s]封块成功（日志数: %d）", bh.BlockID, bh.LogCount)
	return nil
}

// 更新区块的Merkle根（基于当前区块内所有日志的哈希）
func (lc *LogChain) updateMerkleRoot(bh *model.BlockHeaderModel) {
	var logs []model.BlockLogModel
	if err := lc.blockLogModelImpl.GetLogByBlockID(bh.BlockID, &logs); err != nil {
		log.Printf("获取区块[%s]日志失败，Merkle根计算中断: %v", bh.BlockID, err)
		return
	}

	// 收集所有日志的CurrentHash作为Merkle树的叶子节点
	var leafHashes []string
	for _, log := range logs {
		leafHashes = append(leafHashes, log.CurrentHash)
	}

	// 计算Merkle根并更新到区块头
	bh.MerkleRoot = utils.BuildMerkleTree(leafHashes)
	log.Printf("区块[%s]Merkle根已更新: %s", bh.BlockID, bh.MerkleRoot)
}

func (lc *LogChain) SignBlockHeader(header *model.BlockHeaderModel) (string, error) {
	// 序列化区块头（排除签名字段，避免循环依赖）
	headerCopy := *header
	headerCopy.BlockSignature = "" // 临时清空签名
	headerBytes, err := json.Marshal(headerCopy)
	if err != nil {
		return "", fmt.Errorf("区块头序列化失败：%w", err)
	}
	// 计算区块头哈希（SHA-256）
	headerHash := sha256.Sum256(headerBytes)

	// 用根密钥签名
	signatureBytes, err := rsa.SignPKCS1v15(
		r2.Reader,
		lc.rootKey,
		crypto.SHA256,
		headerHash[:],
	)
	if err != nil {
		return "", fmt.Errorf("RSA签名失败：%v", err)
	}

	// 返回16进制签名字符串
	return hex.EncodeToString(signatureBytes), nil
}

func (lc *LogChain) verifyBlockSignature(header *model.BlockHeaderModel) bool {
	// 1. 校验签名是否为空
	if header.BlockSignature == "" {
		log.Printf("区块 %s 签名为空\n", header.BlockID)
		return false
	}

	// 2. 序列化区块头（排除签名字段）
	headerCopy := *header
	headerCopy.BlockSignature = ""
	headerBytes, err := json.Marshal(headerCopy)
	if err != nil {
		log.Printf("区块 %s 头序列化失败：%v\n", header.BlockID, err)
		return false
	}

	// 3. 解码签名字符串为字节数组
	signatureBytes, err := hex.DecodeString(header.BlockSignature)
	if err != nil {
		log.Printf("区块 %s 签名解码失败：%v\n", header.BlockID, err)
		return false
	}

	// 4. 计算区块头哈希并验证签名
	headerHash := sha256.Sum256(headerBytes)
	err = rsa.VerifyPKCS1v15(
		&lc.rootKey.PublicKey,
		crypto.SHA256,
		headerHash[:],
		signatureBytes,
	)
	if err != nil {
		log.Printf("区块 %s 签名验证失败：%v\n", header.BlockID, err)
		return false
	}

	return true
}

// 计算区块头的哈希（排除签名字段，用于链式关联）
func calculateBlockHeaderHash(header *model.BlockHeaderModel) string {
	// 拼接区块头关键字段（BlockID、PrevBlockHash、MerkleRoot、LogCount）
	hashSource := fmt.Sprintf(
		"BlockID=%s&PrevBlockHash=%s&MerkleRoot=%s&LogCount=%d",
		header.BlockID, header.PrevBlockHash, header.MerkleRoot, header.LogCount,
	)
	return utils.CalculateHash(hashSource)
}

// VerifyBlockchain 验证日志链完整性
func (lc *LogChain) VerifyBlockchain(blockLog []data.BlockLogData) (bool, error) {

	var blocks []model.BlockHeaderModel
	if err := lc.blockHeaderModelImpl.GetIdBySignature(&blocks); err != nil {
		return false, fmt.Errorf("获取已封块失败: %w", err)
	}
	// 校验是否有已封块
	if len(blocks) == 0 {
		log.Println("无已封块，区块链为空（视为验证通过）")
		return true, nil
	}

	// 3. 逐个验证区块
	for i := 0; i < len(blocks); i++ {
		currentBlock := blocks[i]

		// 【新增】验证区块内每个日志的哈希有效性
		//for _, log := range blockLog {
		//	calculatedLogHash := utils.CalculateHash(log.LogData)
		//	if calculatedLogHash != log.CurrentHash {
		//		return false, fmt.Errorf("日志[%s]内容被篡改（哈希不匹配）", log.LogID)
		//	}
		//}
		// 验证区块签名
		if !lc.verifyBlockSignature(&currentBlock) {
			return false, fmt.Errorf("区块[%s]签名无效", currentBlock.BlockID)
		}

		// 验证区块间链式关联（非首个区块）
		if i > 0 {
			prevBlock := blocks[i-1]
			prevBlockHeaderHash := calculateBlockHeaderHash(&prevBlock)
			if currentBlock.PrevBlockHash != prevBlockHeaderHash {
				return false, fmt.Errorf("区块[%s]与前区块[%s]关联断裂（哈希不匹配）",
					currentBlock.BlockID, prevBlock.BlockID)
			}
		}
	}
	log.Println("区块链完整性验证通过")
	return true, nil
}

// VerifyLog 验证单条日志的完整性（日志内容、链式关联、Merkle路径、区块签名）
func (lc *LogChain) VerifyLog(logID int, blockID string) (bool, error) {
	var targetBlock model.BlockHeaderModel

	if err := lc.blockHeaderModelImpl.GetBlocksByID(blockID, &targetBlock); err != nil {
		return false, fmt.Errorf("获取区块[%s]失败: %w", blockID, err)
	}

	// 4. 查找目标日志
	var logs []model.BlockLogModel
	if err := lc.blockLogModelImpl.GetLogByBlockID(blockID, &logs); err != nil {
		return false, fmt.Errorf("获取区块[%s]日志失败: %w", blockID, err)
	}

	var currentLog *model.BlockLogModel
	for i := range logs {
		if logs[i].LogID == logID {
			currentLog = &logs[i]
			break
		}
	}
	if currentLog == nil {
		return false, fmt.Errorf("日志[%d]不存在于区块[%s]中", blockID)
	}
	// 5. 验证日志自身哈希（内容未篡改）
	hashSource := fmt.Sprintf(
		"logId=%d&createdAt=%d&name=%s&url=%s&method=%s&data=%s&uid=%d&uname=%s&requestId=%s&type=%d&remoteIp=%s&projectId=%d&result=%s&enName=%s&enResult=%s&prevHash=%s&blockId=%s",
		currentLog.LogID,
		currentLog.CreatedAt,
		currentLog.Name,
		currentLog.URL,
		currentLog.Method,
		currentLog.Data,
		currentLog.UID,
		currentLog.Uname,
		currentLog.RequestID,
		currentLog.Type,
		currentLog.RemoteIP,
		currentLog.ProjectID,
		currentLog.Result,
		currentLog.EnName,
		currentLog.EnResult,
		currentLog.PrevHash,
		currentLog.BlockID,
	)

	calculatedLogHash := utils.CalculateHash(hashSource)
	if calculatedLogHash != currentLog.CurrentHash {
		return false, fmt.Errorf("日志[%d]内容被篡改（哈希不匹配）", currentLog.ID)
	}

	// 验证与前一条日志的关联
	if currentLog.PrevHash != "" {
		var prevLogFound bool
		for _, log := range logs {
			if log.CurrentHash == currentLog.PrevHash {
				prevLogFound = true
				break
			}
		}
		if !prevLogFound {
			return false, fmt.Errorf("日志[%d]的前序哈希[%s]无效", logID, currentLog.PrevHash)
		}
	}

	// 验证区块内部Merkle根
	leafHashes := make([]string, 0, len(logs))
	for _, log := range logs {
		leafHashes = append(leafHashes, log.CurrentHash)
	}
	calculatedMerkleRoot := utils.BuildMerkleTree(leafHashes)
	if calculatedMerkleRoot != targetBlock.MerkleRoot {
		return false, fmt.Errorf("区块[%s]Merkle根无效（存在日志篡改）", blockID)
	}

	// 7. 验证Merkle路径（日志属于当前区块且未被篡改）
	targetLogIndex := -1
	for i, log := range logs {
		if log.LogID == logID {
			targetLogIndex = i
			break
		}
	}
	if targetLogIndex == -1 {
		return false, fmt.Errorf("日志[%d]未在区块[%s]中找到", currentLog.ID, blockID)
	}

	// 生成哈希路径并重新计算Merkle根
	merklePath := getMerklePath(leafHashes, targetLogIndex)
	currentHash := currentLog.CurrentHash
	for _, siblingHash := range merklePath {
		if targetLogIndex%2 == 0 {
			// 偶数索引：当前哈希在左，兄弟哈希在右
			currentHash = utils.CalculateHash(currentHash + siblingHash)
		} else {
			// 奇数索引：当前哈希在右，兄弟哈希在左
			currentHash = utils.CalculateHash(siblingHash + currentHash)
		}
		targetLogIndex /= 2 // 更新索引到上一层
	}
	// 对比计算根与区块存储的Merkle根
	if currentHash != targetBlock.MerkleRoot {
		return false, fmt.Errorf("日志[%d]Merkle路径验证失败", logID)
	}

	// 所有验证通过
	log.Printf("日志为ID[%d]（区块[%s]）验证通过", currentLog.ID, blockID)
	return true, nil
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
			nextLevel = append(nextLevel, utils.CalculateHash(currentHash+nextHash))
		}

		// 更新当前层和目标索引（进入上一层）
		currentLevel = nextLevel
		currentIdx = currentIdx / 2
	}

	return path
}

func (lc *LogChain) CreateLog(logData *model.BlockLogModel) error {

	if logData == nil {
		return errors.New("日志内容不能为空")
	}
	blockID := generateBlockID()
	var currentBlock model.BlockHeaderModel
	err := lc.blockHeaderModelImpl.GetBlocksByID(blockID, &currentBlock)
	//if err != nil {
	//	return fmt.Errorf("查询区块[%s]失败: %w", blockID, err)
	//}
	//if currentBlock.ID == 0 {
	//
	//	// 假设GetBlocksByID在找不到记录时返回gorm.ErrRecordNotFound
	//	if errors.Is(err, gorm.ErrRecordNotFound) {
	//		// 区块不存在，需要创建新区块
	//		newBlock, err := lc.createNewBlock()
	//		if err != nil {
	//			return fmt.Errorf("创建新区块失败：%w", err)
	//		}
	//		// 保存新区块到数据库
	//		if err := lc.blockHeaderModelImpl.GetOrCreateBlock(newBlock); err != nil {
	//			return fmt.Errorf("保存新区块失败: %w", err)
	//		}
	//		currentBlock = *newBlock // 更新当前区块为新创建的区块
	//		fmt.Printf("已创建新区块: %s", currentBlock.BlockID)
	//
	//	} else {
	//		return fmt.Errorf("查询区块[%s]失败: %w", blockID, err)
	//	}
	//}
	// 1. 若当前无区块，初始化新区块
	if err != nil {

		// 假设GetBlocksByID在找不到记录时返回gorm.ErrRecordNotFound
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 区块不存在，需要创建新区块
			newBlock, err := lc.createNewBlock()
			if err != nil {
				return fmt.Errorf("创建新区块失败：%w", err)
			}
			// 保存新区块到数据库
			if err := lc.blockHeaderModelImpl.GetOrCreateBlock(newBlock); err != nil {
				return fmt.Errorf("保存新区块失败: %w", err)
			}
			currentBlock = *newBlock // 更新当前区块为新创建的区块
			fmt.Printf("已创建新区块: %s", currentBlock.BlockID)

		} else {
			return fmt.Errorf("查询区块[%s]失败: %w", blockID, err)
		}
	}

	// 2. 判断当前区块是否应该封块：检查当前分钟是否已过区块 ID 代表的分钟

	todayTimestamp := utils.GetTodayTimestamp()
	blockTimestamp, err := utils.StrToInt(currentBlock.BlockID)
	if err != nil {
		return fmt.Errorf("区块ID[%s]转换失败: %w", currentBlock.BlockID, err)
	}
	// 如果当前时间已经过了区块ID代表的分钟，且区块有日志，则封块
	if todayTimestamp > blockTimestamp && currentBlock.LogCount > 0 {
		if err := lc.finalizeBlock(&currentBlock); err != nil {
			return fmt.Errorf("区块[%s]封块失败: %w", currentBlock.BlockID, err)
		}
		log.Printf("区块[%s]已封块（日志数: %d）", currentBlock.BlockID, currentBlock.LogCount)

		// 重新创建新区块
		block, err := lc.createNewBlock()
		if err != nil {
			return fmt.Errorf("封块后创建新区块失败: %w", err)
		}
		currentBlock = *block
	}
	// 3. 创建日志记录
	// 生成日志ID：区块ID + 5位序号（支持最多99999条日志）
	logCount := currentBlock.LogCount + 1
	//logSeq := fmt.Sprintf("%05d", logCount)                    // 5位序号，如：00001, 00002, ..., 99999
	//logID := fmt.Sprintf("%d%s", currentBlock.BlockID, logSeq) // 区块ID + 5位序号
	logID := logCount
	// 4. 计算前一条日志的哈希（确保日志间链式关联）
	var prevLogHash string
	// 确保当前区块有日志且索引有效
	if currentBlock.LogCount > 0 {
		var latestLog model.BlockLogModel
		if err := lc.blockLogModelImpl.GetEndLog(currentBlock.BlockID, &latestLog); err != nil {
			return fmt.Errorf("获取区块[%s]最新日志失败: %w", currentBlock.BlockID, err)
		}
		prevLogHash = latestLog.CurrentHash
	}

	hashSource := fmt.Sprintf(
		"logId=%d&createdAt=%d&name=%s&url=%s&method=%s&data=%s&uid=%d&uname=%s&requestId=%s&type=%d&remoteIp=%s&projectId=%d&result=%s&enName=%s&enResult=%s&prevHash=%s&blockId=%s",
		logID,
		logData.CreatedAt,
		logData.Name,
		logData.URL,
		logData.Method,
		logData.Data,
		logData.UID,
		logData.Uname,
		logData.RequestID,
		logData.Type,
		logData.RemoteIP,
		logData.ProjectID,
		logData.Result,
		logData.EnName,
		logData.EnResult,
		prevLogHash,
		currentBlock.BlockID,
	)
	// 6. 计算日志哈希并初始化日志对象
	logHash := utils.CalculateHash(hashSource) // 基于日志内容计算哈希
	newLog := &model.BlockLogModel{
		CreatedAt:   time.Now().Unix(),
		PrevHash:    prevLogHash,
		CurrentHash: logHash, // 记录当前日志哈希
		BlockID:     currentBlock.BlockID,
	}

	// 6. 保存日志到数据库
	if err := lc.blockLogModelImpl.Create(newLog); err != nil {
		return fmt.Errorf("区块[%s],保存日志[%d]失败: %w", currentBlock.BlockID, logID, err)
	}

	// 8. 更新区块信息（日志计数 + Merkle根）
	currentBlock.LogCount = logCount   // 直接使用计算好的logCount
	lc.updateMerkleRoot(&currentBlock) // 基于最新日志重新计算Merkle根

	// 8. 每次添加日志后都对区块头进行签名
	signature, err := lc.SignBlockHeader(&currentBlock)
	if err != nil {
		return fmt.Errorf("区块[%s]签名失败: %w", currentBlock.BlockID, err)
	}
	currentBlock.BlockSignature = signature

	// 9. 更新数据库中的区块信息
	if err := lc.blockHeaderModelImpl.UpdateCurrentBlock(&currentBlock); err != nil {
		return fmt.Errorf("更新区块信息失败 (区块ID: %s): %w", currentBlock.BlockID, err)
	}
	log.Printf("日志创建成功（ID: %d, 区块: %s）", logID, currentBlock.BlockID)
	return nil
}

// 创建新区块（初始化区块头和区块体）
func (lc *LogChain) createNewBlock() (*model.BlockHeaderModel, error) {
	blockID := generateBlockID() // 生成19位唯一区块ID
	var prevBlockHash string     // 前一个区块头的哈希

	count, err := lc.blockHeaderModelImpl.GetBlockCount()
	if err != nil {
		return nil, fmt.Errorf("获取区块数量失败：%v", err)
	}

	// 若为首个区块，前哈希设为固定值；否则从数据库获取最新区块的头哈希
	if count == 0 {
		prevBlockHash = global.INIT_LOGHASH // 首个区块的前哈希固定值
	} else {
		var latestBlock model.BlockHeaderModel
		if err := lc.blockHeaderModelImpl.GetLatestBlock(&latestBlock); err != nil {
			return nil, fmt.Errorf("获取最新区块失败: %w", err)
		}
		prevBlockHash = calculateBlockHeaderHash(&latestBlock)
	}

	// 初始化区块头（MerkleRoot初始为空，后续添加日志时更新）
	return &model.BlockHeaderModel{
		BlockID:        blockID,
		PrevBlockHash:  prevBlockHash,
		MerkleRoot:     "",
		BlockSignature: "", // 确保签名为空
		LogCount:       0,
	}, nil
}

func generateBlockID() string {
	// 获取当前日期的时间戳（对齐到天）
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	timestamp := todayStart.Unix() // 10位秒级时间戳，对齐到天
	return strconv.FormatInt(timestamp, 10)
}
