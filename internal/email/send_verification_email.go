package email

type SendVerificationEmailUseCase interface {
	Send(email string, username string, code string) error
}

type sendVerificationEmailUseCase struct {
	*Sender
}

func NewSendVerificationEmailUseCase(sender *Sender) SendVerificationEmailUseCase {
	return &sendVerificationEmailUseCase{sender}
}

func (u *sendVerificationEmailUseCase) Send(email string, username string, code string) error {
	err := u.SendVerificationEmail(email, username, code)
	if err != nil {
		err = u.SendVerificationEmail(email, username, code)
		if err == nil {
			return nil
		}
	}

	return err
}
