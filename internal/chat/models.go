//// File: internal/chat/models.go
//
package chat

//
//import (
//	"time"
//
//	"google.golang.org/protobuf/types/known/timestamppb"
//)
//
//type ChatDomain struct {
//	ChatId        string
//	ChatType      string // "private", "public", or "direct"
//	ChatName      string
//	Username      string // For public chats
//	InvitationUrl string // For private chats
//	CreatedAt     *timestamppb.Timestamp
//	CreatedBy     string
//}
//
//type MessageDomain struct {
//	MessageId        string
//	ChatId           string
//	SenderId         string
//	Content          string
//	SentAt           *timestamppb.Timestamp
//	Status           MessageStatusDomain
//	ReplyToMessageId string
//	DeliveredAt      *timestamppb.Timestamp
//	ReadAt           *timestamppb.Timestamp
//}
//
//type ChatParticipant struct {
//	ChatId   string
//	UserId   string
//	Role     string // "owner", "admin", or "member"
//	JoinedAt time.Time
//}
//
//type ChatInvitationDomain struct {
//	InvitationId  string
//	ChatId        string
//	InviterId     string
//	InviteeId     string
//	InvitationUrl string
//	CreatedAt     *timestamppb.Timestamp
//	ExpiresAt     *timestamppb.Timestamp
//	IsActive      bool
//}
//
//type StatusUpdate struct {
//	UserId    string
//	ChatId    string
//	Status    UserStatus
//	Activity  ActivityStatus
//	Timestamp *timestamppb.Timestamp
//}
//
//// Enum types (these should match your protobuf enum definitions)
//
//type MessageStatusDomain int32
//
//const (
//	MessageStatus_SENT MessageStatusDomain = iota
//	MessageStatus_DELIVERED
//	MessageStatus_READ
//)
//
//type UserStatus int32
//
//const (
//	UserStatus_OFFLINE UserStatus = iota
//	UserStatus_ONLINE
//)
//
//type ActivityStatus int32
//
//const (
//	ActivityStatus_NONE ActivityStatus = iota
//	ActivityStatus_TYPING
//	ActivityStatus_SELECTING_IMAGE
//	ActivityStatus_SELECTING_STICKER
//)
//
//// Request and Response types for additional methods
//
//type CreatePublicGroupChatRequestDomain struct {
//	Name      string
//	Username  string
//	CreatorId string
//}
//
//type CreatePublicGroupChatResponseDomain struct {
//	Chat *ChatDomain
//}
//
//type CreatePrivateGroupChatRequestDomain struct {
//	Name      string
//	CreatorId string
//}
//
//type CreatePrivateGroupChatResponseDomain struct {
//	Chat *ChatDomain
//}
//
//type JoinPublicGroupChatRequestDomain struct {
//	Username string
//	UserId   string
//}
//
//type JoinPublicGroupChatResponseDomain struct {
//	Success bool
//}
//
//type CreateChatInvitationRequestDomain struct {
//	ChatId    string
//	InviterId string
//	InviteeId string
//	ExpiresIn *time.Duration
//}
//
//type CreateChatInvitationResponseDomain struct {
//	Invitation *ChatInvitation
//}
//
//type JoinPrivateGroupChatRequestDomain struct {
//	InvitationUrl string
//	UserId        string
//}
//
//type JoinPrivateGroupChatResponseDomain struct {
//	Success bool
//}
