package models

import (
	"database/sql"
)

type Link struct {
	Userlink     string `json:"userlink"`
	Tolink       string `json:"tolink"`
	Owner        string `json:"owner"`
	Redirections int    `json:"redirections"`
}

type LinkModel struct {
	DB *sql.DB
}

func (m *LinkModel) Insert(userlink string, tolink string, owner string) (int, error) {
	query := `INSERT INTO links (userlink, tolink, owner)
		VALUES($1, $2, $3) RETURNING id`

	var pk int
	err := m.DB.QueryRow(query, userlink, tolink, owner).Scan(&pk)
	if err != nil {
		return 0, err
	}
	return pk, nil
}

func (m *LinkModel) Delete(tolink string) error {
	query := `DELETE FROM links 
	WHERE tolink = $1`

	_, err := m.DB.Exec(query, tolink)
	if err != nil {
		return err
	}
	return nil
}

func (m *LinkModel) Update(tolink string) (bool, error) {
	query := `UPDATE links SET redirections = redirections + 1 WHERE tolink = $1`
	_, err := m.DB.Exec(query, tolink)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (m *LinkModel) Exist(tolink string) (bool, error) {
	query := `SELECT EXISTS (SELECT 1 FROM links WHERE tolink = $1)`

	var check bool
	err := m.DB.QueryRow(query, tolink).Scan(&check)
	if err != nil {
		return false, err
	}
	return check, nil
}

func (m *LinkModel) Deploy() error {
	query := `CREATE TABLE IF NOT EXISTS links (
		id SERIAL PRIMARY KEY,
		userlink VARCHAR(100) NOT NULL,
		tolink VARCHAR(100) NOT NULL,
		owner VARCHAR(100) NOT NULL,
		FOREIGN KEY (owner) REFERENCES users(username),
		redirections INT DEFAULT 0
	);`

	_, err := m.DB.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

func (m *LinkModel) SelectToTransfer(tolink string) (*Link, error) {
	query := `SELECT userlink, owner FROM links WHERE tolink = $1`
	l := &Link{}
	err := m.DB.QueryRow(query, tolink).Scan(&l.Userlink, &l.Owner)
	if err != nil {
		return nil, err
	}
	return l, err
}

func (m *LinkModel) SelectAllFromUser(owner string) ([]*Link, error) {
	query := `SELECT userlink, tolink, redirections FROM links WHERE owner = $1 ORDER BY id ASC`

	rows, err := m.DB.Query(query, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	links := []*Link{}

	for rows.Next() {
		l := &Link{}
		err = rows.Scan(&l.Userlink, &l.Tolink, &l.Redirections)
		if err != nil {
			return nil, err
		}
		links = append(links, l)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return links, nil
}
