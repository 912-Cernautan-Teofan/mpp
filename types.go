package main

import (
	"time"

	"gorm.io/plugin/soft_delete"
)

type BaseModel struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt soft_delete.DeletedAt `gorm:"index"`
}

type Employee struct {
	ID        uint   `json:"id" gorm:"autoIncrement"`
	FirstName string `json:"first_name" faker:"first_name"`
	LastName  string `json:"last_name"  faker:"last_name"`
	Email     string `json:"email" faker:"email"`
	Age       int    `json:"age" faker:"boundary_start=18, boundary_end=65"`
	Salary    int    `json:"salary" faker:"boundary_start=1000, boundary_end=6000"`
	Phone     string `json:"phone" faker:"phone_number"`
	Tasks     []Task `json:"-" gorm:"foreignKey:EmployeeID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

type Task struct {
	ID          uint   `json:"id" gorm:"autoIncrement"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Deadline    string `json:"deadline"`
	Status      string `json:"status"`
	EmployeeID  uint   `json:"employee_id"`
}

type ConnectionTest struct {
	Valid string `json:"valid" Gorm:"type:char; primarykey; not null; default:'Y'"`
}

type Role struct {
	ID   uint   `gorm:"autoIncrement"`
	Name string `gorm:"unique"`
}

type User struct {
	ID       uint   `gorm:"autoIncrement"`
	Username string `gorm:"unique"`
	Password string
	RoleID   uint
	Role     Role `gorm :foreignKey:RoleID;references:RoleID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;`
}

type Session struct {
	ID         uint `gorm:"autoIncrement"`
	UserID     uint
	User       User   `gorm :foreignKey:UserID;references:UserID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;`
	Token      string `gorm:"unique"`
	ValidUntil time.Time
}

type UserSession struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Name     string `json:"rolename"`
}

type UserRole struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	RoleID   uint   `json:"roleid"`
	Rolename string `json:"rolename"`
}
type UserDetails struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Rolename string `json:"rolename"`
}
