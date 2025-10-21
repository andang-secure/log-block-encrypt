package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// BuildMerkleTree 构建Merkle树并返回根哈希（两两组合，递归计算）
func BuildMerkleTree(leafHashes []string) string {
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
		parentHash := CalculateHash(currentHash + nextHash)
		parentHashes = append(parentHashes, parentHash)
	}

	// 4. 递归计算上一层，直到得到根哈希
	return BuildMerkleTree(parentHashes)
}
func CalculateHash(data string) string {
	hashBytes := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hashBytes[:])
}

func GetTodayTimestamp() int64 {
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	return todayStart.Unix()
}

func StrToInt(str string) (int64, error) {
	result, err := strconv.ParseInt(str, 10, 64)
	return result, err
}
