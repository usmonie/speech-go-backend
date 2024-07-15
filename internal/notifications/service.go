package notifications

import (
//	"fmt"
//	"speech/internal/auth"
)

type NotificationService interface {
	SendNewSessionNotification(userID, deviceToken, sessionInfo string) error
}

type RealNotificationService struct {
	fcmClient  FCMClient
	apnsClient APNSClient
}

func NewRealNotificationService(fcmClient FCMClient, apnsClient APNSClient) *RealNotificationService {
	return &RealNotificationService{
		fcmClient:  fcmClient,
		apnsClient: apnsClient,
	}
}

type FCMClient interface {
	Send(deviceToken, message string) error
}

// APNSClient is a placeholder for a real Apple Push Notification Service client
type APNSClient interface {
	Send(deviceToken, message string) error
}

//func (s *RealNotificationService) SendNewSessionNotification(devices auth.Device) error {
//	message := fmt.Sprintf("New login detected for your account. Details: %s", sessionInfo)
//
//	// Determine the device type (Android or iOS) based on the token format
//	// This is a simplistic approach; in a real-world scenario, you'd likely store the device type with the token
//	if len(deviceToken) > 64 {
//		// Assume FCM (Android)
//		return s.fcmClient.Send(deviceToken, message)
//	} else {
//		// Assume APNS (iOS)
//		return s.apnsClient.Send(deviceToken, message)
//	}
//}
