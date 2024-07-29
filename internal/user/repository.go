package user

import (
	"context"
	"database/sql"
	"speech/infrastructure"
	"speech/internal/user/storage"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, user *User) (rUser *User, err error)
	GetByID(ctx context.Context, id *uuid.UUID) (*User, error)
	GetByUsername(ctx context.Context, username string) ([]*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id *uuid.UUID) error
}

type repository struct {
	*sql.DB
	userSaver    storage.Saver
	userProvider storage.Provider
	userUpdater  storage.Updater
	userDeleter  storage.Deleter
}

func NewRepository(
	db *sql.DB,
	userSaver storage.Saver,
	userProvider storage.Provider,
	userUpdater storage.Updater,
	userDeleter storage.Deleter,
) Repository {
	return &repository{
		DB:           db,
		userSaver:    userSaver,
		userProvider: userProvider,
		userUpdater:  userUpdater,
		userDeleter:  userDeleter,
	}
}

func (r *repository) Create(ctx context.Context, user *User) (rUser *User, err error) {
	err = infrastructure.WithTransaction(r.DB, ctx, func(tx *sql.Tx) error {
		dbUser, err := r.userSaver.SaveUser(tx, ConvertUserToDbUser(user))
		rUser = ConvertDBUserToUser(dbUser)

		return err
	})

	return rUser, err
}

func (r *repository) GetByID(ctx context.Context, id *uuid.UUID) (*User, error) {
	dbUser, err := r.userProvider.UserByID(id)
	if err != nil {
		return nil, err
	}
	return ConvertDBUserToUser(dbUser), nil
}

func (r *repository) GetByUsername(ctx context.Context, username string) ([]*User, error) {
	dbUsers, err := r.userProvider.UserByUsername(username)
	if err != nil {
		return nil, infrastructure.ErrUsersNotFound
	}

	users := make([]*User, len(dbUsers))
	for i, dbUser := range dbUsers {
		users[i] = ConvertDBUserToUser(dbUser)
	}

	return users, nil
}

func (r *repository) GetByEmail(ctx context.Context, email string) (*User, error) {
	user, err := r.userProvider.UserByEmail(email)
	if err != nil {
		return nil, err
	}

	return ConvertDBUserToUser(user), nil
}

func (r *repository) Update(ctx context.Context, user *User) error {
	return infrastructure.WithTransaction(r.DB, ctx, func(tx *sql.Tx) error {
		_, err := r.userUpdater.UpdateUser(tx, ConvertUserToDbUser(user))
		return err
	})
}

func (r *repository) Delete(ctx context.Context, id *uuid.UUID) error {
	return infrastructure.WithTransaction(r.DB, ctx, func(tx *sql.Tx) error {
		return r.userDeleter.DeleteUser(tx, id)
	})
}
