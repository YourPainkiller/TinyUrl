package models

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserModel struct {
	DB *sql.DB
}

func (m *UserModel) Auth(username string, password string) (int, error) {
	query := `SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)`

	var check bool
	err := m.DB.QueryRow(query, username).Scan(&check)
	if err != nil {
		return 0, err
	}
	if !check {
		return -1, nil
	}

	query = `SELECT password FROM users WHERE username = $1`
	var hashedPassword string
	err = m.DB.QueryRow(query, username).Scan(&hashedPassword)
	if err != nil {
		return 0, err
	}
	if hashedPassword != Hash(password) {
		return -1, nil
	}
	return 1, nil
}

func (m *UserModel) Insert(username string, password string) (int, error) {
	query := `INSERT INTO users (username, password)
	VALUES($1, $2) RETURNING id`

	var pk int
	err := m.DB.QueryRow(query, username, password).Scan(&pk)
	if err != nil {
		return 0, err
	}
	return pk, nil
}

func (m *UserModel) Select(username string) (int, error) {
	query := `SELECT id FROM users WHERE username = $1`

	var userID int
	err := m.DB.QueryRow(query, username).Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func (m *UserModel) Exist(username string) (bool, error) {
	query := `SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)`

	var check bool
	err := m.DB.QueryRow(query, username).Scan(&check)
	if err != nil {
		return false, err
	}
	return check, nil
}

func (m *UserModel) Deploy() error {
	query := `CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(100) NOT NULL UNIQUE,
		password VARCHAR(100) NOT NULL
	);`
	_, err := m.DB.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

func Hash(str string) string {
	h := sha256.New()
	h.Write([]byte(str))
	//TODO: Передавать секрет вместо nil
	fh := h.Sum(nil)
	temp := hex.EncodeToString(fh)
	return string(temp)
}
