package log_block

import (
	"chain_log_demo/data"
	"chain_log_demo/global"
	"chain_log_demo/model"
	"chain_log_demo/utils"
	"crypto"
	r2 "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"log"
	"strconv"
	"time"
)

type LogChainConf struct {
	RootKey              *rsa.PrivateKey
	DB                   *gorm.DB
	blockHeaderTableName string
	blockLogTableName    string
}

func NewLogChain(conf *LogChainConf) (*LogChain, error) {
	global.DB = conf.DB
	global.BlockLogTableName = conf.blockLogTableName
	global.BlockHeaderTableName = conf.blockHeaderTableName
	if global.DB == nil {
		return nil, errors.New("数据库连接未初始化")
	}
	if global.BlockLogTableName == "" {
		return nil, errors.New("日志表未初始化")
	}
	if global.BlockHeaderTableName == "" {
		return nil, errors.New("区块表未初始化")
	}
	// 2. 创建LogChain实例
	lc := &LogChain{
		rootKey: conf.RootKey,
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

			fmt.Printf("下次自动封块将在 %s 执行\n", nextMidnight.Format("2006-01-02 15:04:05"))

			// 等待到下一个凌晨 00:00
			time.Sleep(durationUntilNextMidnight)

			// 执行自动封块
			lc.AutoSealBlocks()
		}
	}()
}

// AutoSealBlocks 自动封块方法
func (lc *LogChain) AutoSealBlocks() {

	// 从数据库查询所有未封块的区块
	var unsealedBlocks []model.BlockHeaderModel
	err := lc.blockHeaderModelImpl.GetAll(unsealedBlocks)
	if err != nil {
		log.Println("未封块的区块查询失败:", err)
		return
	}

	// 获取当前日期的时间戳（对齐到天）
	//now := time.Now()
	//todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	//todayTimestamp := todayStart.Unix()
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
			if lc.finalizeBlock(&blockHeader) != nil {
				log.Printf("更新区块 %v 状态失败: %v\n", blockHeader.BlockID, err)
				continue
			}
			log.Printf("[自动封块] 区块 %v 已封块（按天封块）\n\n", blockHeader.BlockID)
		}
	}
}

// 封块操作（对区块头签名，持久化存储区块）
func (lc *LogChain) finalizeBlock(bh *model.BlockHeaderModel) error {

	// 对区块头进行签名
	signature, err := lc.SignBlockHeader(bh)
	if err != nil {
		fmt.Printf("区块 %s 签名失败: %v\n", bh.BlockID, err)
		return fmt.Errorf("区块 %s 签名失败: %v", bh.BlockID, err)
	}
	// 2. 确保Merkle根已计算（避免空区块）
	if bh.MerkleRoot == "" && bh.LogCount > 0 {
		lc.updateMerkleRoot(bh)
	}

	// 3. 注意：不再在这里签名，因为每次添加日志时已经签名了
	// 确保区块有签名
	if bh.BlockSignature == "" {
		return fmt.Errorf("区块头缺少签名")
	}

	// 4. 持久化存储区块
	err = lc.blockHeaderModelImpl.Update(bh.BlockID, signature)
	if err != nil {
		return fmt.Errorf("区块 %s 持久化失败: %v", bh.BlockID, err)
	}
	fmt.Printf("区块 %s 已封块，包含 %d 条日志\n", bh.BlockID, bh.LogCount)

	return nil
}

// 更新区块的Merkle根（基于当前区块内所有日志的哈希）
func (lc *LogChain) updateMerkleRoot(bh *model.BlockHeaderModel) {
	var logs []model.BlockLogModel
	err := lc.blockLogModelImpl.GetLogByBlockID(bh.BlockID, &logs)
	if err != nil {
		return
	}

	// 收集所有日志的CurrentHash作为Merkle树的叶子节点
	var leafHashes []string
	for _, log := range logs {
		leafHashes = append(leafHashes, log.CurrentHash)
	}

	// 计算Merkle根并更新到区块头
	merkleRoot := utils.BuildMerkleTree(leafHashes)
	bh.MerkleRoot = merkleRoot
}

func (lc *LogChain) SignBlockHeader(header *model.BlockHeaderModel) (string, error) {
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
		&lc.rootKey.PublicKey,
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
	// 1. 从数据库收集所有已封块
	//var blocks []*Block

	var block []model.BlockHeaderModel
	err := lc.blockHeaderModelImpl.GetIdBySignature(block)
	if err != nil {
		fmt.Printf("暂未获取到封块：%v", err)
	}

	// 校验是否有已封块
	if len(block) == 0 {
		fmt.Println("无已封块，区块链为空")
		return true, nil
	}

	// 3. 逐个验证区块
	for i := 0; i < len(block); i++ {
		currentBlock := block[i]
		blockID := currentBlock.BlockID

		// 【新增】验证区块内每个日志的哈希有效性
		for _, log := range blockLog {
			calculatedLogHash := utils.CalculateHash(log.LogData)
			if calculatedLogHash != log.CurrentHash {

				return false, fmt.Errorf("日志链Hash验证失败：日志 %v 内容被篡改\n", log.LogID)
			}
		}

		// 验证区块签名
		if !lc.verifyBlockSignature(&currentBlock) {
			fmt.Printf("区块链验证失败：区块 %v 签名无效\n", blockID)
			return false, fmt.Errorf("验证失败，此日志区块 %v  签名无效", blockID)
		}

		// 验证区块间链式关联（非首个区块）
		if i > 0 {
			prevBlock := block[i-1]
			prevBlockHeaderHash := calculateBlockHeaderHash(&prevBlock)
			if currentBlock.PrevBlockHash != prevBlockHeaderHash {
				fmt.Printf("区块链验证失败：区块 %v 与前区块 %v 关联断裂\n",
					blockID, prevBlock.BlockID)
				fmt.Printf("- 当前区块存储的前哈希：%s\n- 前区块头实际哈希：%s\n",
					currentBlock.PrevBlockHash, prevBlockHeaderHash)
				return false, fmt.Errorf("验证失败，此日志区块 %v  链断裂", blockID)
			}
		}
	}
	return true, nil
}

// VerifyLog 验证单条日志的完整性（日志内容、链式关联、Merkle路径、区块签名）
func (lc *LogChain) VerifyLog(logID int, blockID string) (bool, error) {
	var targetBlock model.BlockHeaderModel

	err := lc.blockHeaderModelImpl.GetBlocksByID(blockID, &targetBlock)
	if err != nil {
		fmt.Printf("暂未获取到封块：%v", err)
	}

	log.Println("正在验证区块 ...", targetBlock)

	// 4. 查找目标日志
	var logs []model.BlockLogModel
	err = lc.blockLogModelImpl.GetLogByBlockID(blockID, &logs)
	if err != nil {
		return false, fmt.Errorf("暂未获取到日志：%v", err)
	}

	var currentLog model.BlockLogModel
	for _, log := range logs {
		if log.LogID == logID {
			currentLog = log
			break
		}
	}
	// 5. 验证日志自身哈希（内容未篡改）
	calculatedLogHash := utils.CalculateHash("")
	if calculatedLogHash != currentLog.CurrentHash {
		return false, fmt.Errorf("验证Hash失败,日志 %v 内容被篡改", logID)
	}

	// 6. 验证与前一条日志的链式关联（非第一条日志）
	if currentLog.PrevHash != "" {
		var prevLog *model.BlockLogModel
		for _, log := range logs {
			if log.CurrentHash == currentLog.PrevHash {
				prevLog = &log
				break
			}
		}
		if prevLog == nil {
			return false, fmt.Errorf("日志 %v 的前序日志哈希无效：%s\n", logID, currentLog.PrevHash)
		}
	}

	// 验证区块内部Merkle根
	var leafHashes1 []string
	for _, log := range logs {
		leafHashes1 = append(leafHashes1, log.CurrentHash)
	}
	calculatedMerkleRoot := utils.BuildMerkleTree(leafHashes1)
	if calculatedMerkleRoot != targetBlock.MerkleRoot {
		return false, fmt.Errorf("验证失败，此日志区块 %v  内部日志存在篡改，Merkle根无效", blockID)
	}

	// 7. 验证Merkle路径（日志属于当前区块且未被篡改）
	var leafHashes []string
	var targetLogIndex int
	for idx, log := range logs {
		leafHashes = append(leafHashes, log.CurrentHash)
		if log.LogID == logID {
			targetLogIndex = idx
		}
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
		targetLogIndex = targetLogIndex / 2 // 更新索引到上一层
	}
	// 对比计算根与区块存储的Merkle根
	if currentHash != targetBlock.MerkleRoot {
		return false, fmt.Errorf("日志 %v 的Merkle路径验证失败", logID)
	}

	// 所有验证通过
	fmt.Printf("日志 %s 验证通过（所属区块：%s）\n", logID, blockID)
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
			parentHash := utils.CalculateHash(currentHash + nextHash)
			nextLevel = append(nextLevel, parentHash)
		}

		// 更新当前层和目标索引（进入上一层）
		currentLevel = nextLevel
		currentIdx = currentIdx / 2
	}

	return path
}

func (lc *LogChain) CreateLog(logData string) error {

	if logData == "" {
		return errors.New("日志内容不能为空")
	}
	blockID := generateBlockID()
	var currentBlock model.BlockHeaderModel
	err := lc.blockHeaderModelImpl.GetBlocksByID(blockID, &currentBlock)
	// 1. 若当前无区块，初始化新区块
	if err != nil {
		// 假设GetBlocksByID在找不到记录时返回gorm.ErrRecordNotFound
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 区块不存在，需要创建新区块
			newBlock, err := lc.createNewBlock()
			if err != nil {
				return fmt.Errorf("创建新区块失败：%v", err)
			}
			// 保存新区块到数据库
			if err := lc.blockHeaderModelImpl.GetOrCreateBlock(newBlock); err != nil {
				return fmt.Errorf("保存新区块失败: %w", err)
			}
			currentBlock = *newBlock // 更新当前区块为新创建的区块
			log.Printf("已创建新区块: %s", currentBlock.BlockID)

		} else {
			return fmt.Errorf("获取区块失败：%v", err)
		}
	}

	// 2. 判断当前区块是否应该封块：检查当前分钟是否已过区块 ID 代表的分钟

	todayTimestamp := utils.GetTodayTimestamp()
	blockMinuteTimestamp, err := utils.StrToInt(currentBlock.BlockID)
	if err != nil {
		return fmt.Errorf("区块ID转换失败：%v", err)
	}
	// 如果当前时间已经过了区块ID代表的分钟，且区块有日志，则封块
	if todayTimestamp > blockMinuteTimestamp && currentBlock.LogCount > 0 {
		if err := lc.finalizeBlock(&currentBlock); err != nil {
			return fmt.Errorf("封块失败 (ID: %s): %w", currentBlock.BlockID, err)
		}
		log.Printf("[自动封块] 区块 %s 已封块（包含 %d 条日志）", currentBlock.BlockID, currentBlock.LogCount)

		// 重新创建新区块
		block, err := lc.createNewBlock()
		if err != nil {
			return fmt.Errorf("创建新区块失败：%v", err)
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

		err := lc.blockLogModelImpl.GetEndLog(currentBlock.BlockID, &latestLog)
		if err != nil {
			return fmt.Errorf("获取最新日志失败：%v", err)
		}
		prevLogHash = latestLog.CurrentHash
	}

	// 6. 计算日志哈希并初始化日志对象
	logHash := utils.CalculateHash(logData) // 基于日志内容计算哈希
	newLog := &model.BlockLogModel{
		LogID:       logID,
		LogData:     logData, // 存储原始日志内容（用于后续验证）
		CreatedAt:   time.Now().Unix(),
		PrevHash:    prevLogHash,
		CurrentHash: logHash, // 记录当前日志哈希
	}

	// 6. 保存日志到数据库
	if err := lc.blockLogModelImpl.Create(newLog); err != nil {
		return fmt.Errorf("保存日志失败：%v", err)
	}

	// 8. 更新区块信息（日志计数 + Merkle根）
	currentBlock.LogCount = logCount   // 直接使用计算好的logCount
	lc.updateMerkleRoot(&currentBlock) // 基于最新日志重新计算Merkle根

	// 8. 每次添加日志后都对区块头进行签名
	signature, err := lc.SignBlockHeader(&currentBlock)
	if err != nil {
		return fmt.Errorf("区块头签名失败 (区块ID: %s): %w", currentBlock.BlockID, err)
	} else {
		currentBlock.BlockSignature = signature
	}

	// 9. 更新数据库中的区块信息
	if err := lc.blockHeaderModelImpl.UpdateCurrentBlock(&currentBlock); err != nil {
		return fmt.Errorf("更新区块信息失败 (区块ID: %s): %w", currentBlock.BlockID, err)
	}
	log.Printf("日志创建成功 (日志ID: %v, 区块ID: %s)", logID, currentBlock.BlockID)
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
		err := lc.blockHeaderModelImpl.GetLatestBlock(&latestBlock)
		if err != nil {
			return nil, fmt.Errorf("获取最新区块失败：%v", err)
		}
		prevBlockHash = calculateBlockHeaderHash(&model.BlockHeaderModel{
			BlockID:        latestBlock.BlockID,
			PrevBlockHash:  latestBlock.PrevBlockHash,
			MerkleRoot:     latestBlock.MerkleRoot,
			BlockSignature: latestBlock.BlockSignature,
			LogCount:       latestBlock.LogCount,
		})
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
