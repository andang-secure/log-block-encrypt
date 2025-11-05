package data

type BlockLogData struct {
	LogID       int64
	LogData     string
	PrevHash    string
	CurrentHash string
}

type BlockLogRequest struct {
	ID        int64  `json:"id"`         // ID
	CreatedAt int64  `json:"created_at"` // 创建时间
	UpdatedAt int64  `json:"updated_at"` // 修改时间
	Name      string `json:"name"`       //账号名称
	EnName    string `json:"en_name"`    //英文名称
	URL       string `json:"url"`        //账号名称
	Method    string `json:"method"`     //备注
	Data      string `json:"data"`
	UID       int64  `json:"uid"`
	Uname     string `json:"uname"`
	RequestID string `json:"request_id"`
	Type      int    `json:"type"` // 0:web 1:open
	RemoteIP  string `json:"remote_ip"`
	ProjectID int64  `json:"project_id"`
	Result    string `json:"result"`
	EnResult  string ` json:"en_result"`
}
