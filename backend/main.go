package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/rs/cors"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

var RoleList []Role
var UserList []User
var SessionList []Session

var EmployeeList []Employee
var TaskList []Task

var EmployeeUpdate bool = false
var TaskUpdate bool = false

var db *gorm.DB
var err error

func init() {
	query := url.Values{}
	query.Add("database", "MPP_DB")

	conn := &url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword("mpp", "mpp"),
		Host:     fmt.Sprintf("%s:%d", "localhost", 1433),
		RawQuery: query.Encode(),
	}
	db, err = gorm.Open(sqlserver.Open(conn.String()))

	if err != nil {
		log.Fatal(err)
	}

	sqldb, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}

	err = sqldb.Ping()
	if err != nil {
		log.Fatal(err)
	}

	//db.AutoMigrate(&RoleList, &UserList, &SessionList)
	//db.AutoMigrate(&EmployeeList, &TaskList)

	// RoleList = append(RoleList, Role{Name: "User"}, Role{Name: "Manager"}, Role{Name: "Admin"})

	// UserList = append(UserList,
	// 	User{Username: "user", Password: "user", RoleID: 1},
	// 	User{Username: "manager", Password: "manager", RoleID: 2},
	// 	User{Username: "admin", Password: "admin", RoleID: 3})

	// db.Create(&RoleList)
	// db.Create(&UserList)

	fmt.Println("DB connected")

	fmt.Print("Data load test: ")

	fmt.Println("Loaded")

	fmt.Print("Loading data: ")
	db.Find(&EmployeeList)
	db.Find(&TaskList)
	db.Find(&RoleList)
	db.Find(&UserList)
	db.Find(&SessionList)
	fmt.Println("Loaded")
	fmt.Println(EmployeeList)
}

func muxHandleSessionsAPI(mux *http.ServeMux) {

	mux.HandleFunc("POST /api/Login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("POST /api/Login")
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		db.Where("username = ? AND password = ?", user.Username, user.Password).Find(&user)
		if user.ID == 0 {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		var session Session
		session.UserID = user.ID

		db.Find(&session, "user_id = ?", user.ID)

		if session.ID != 0 {
			ret := db.Where("user_id = ?", user.ID).Delete(&Session{})
			fmt.Print("Past Session Deleted: ")
			fmt.Println(ret.RowsAffected)
			session.ID = 0
		}

		session.Token = uuid.New().String()
		session.ValidUntil = time.Now().Add(1 * time.Hour)
		db.Create(&session)
		db.Last(&session)
		SessionList = append(SessionList, session)

		var userSession UserSession
		db.Table("sessions").
			Select("sessions.token, users.username ,roles.name").
			Joins("JOIN users ON sessions.user_id = users.id").
			Joins("JOIN roles ON users.role_id = roles.id").
			Where("sessions.token = ?", session.Token).
			Scan(&userSession)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userSession)
	})

	mux.HandleFunc("GET /api/Logout", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("GET /api/Logout")
		token := r.Header.Get("Authorization")
		for i, session := range SessionList {
			if session.Token == token {
				SessionList = append(SessionList[:i], SessionList[i+1:]...)
				db.Delete(&Session{}, session.ID)
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode("Logged out")
	})

	mux.HandleFunc("GET /api/Session/Validate", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("GET /api/Session/Validate")
		token := r.Header.Get("Authorization")
		for _, session := range SessionList {
			if session.Token == token {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode("Valid")
				return
			}
		}
		http.Error(w, "Invalid session", http.StatusUnauthorized)
	})

	mux.HandleFunc("GET /api/Session/GetUsers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("GET /api/Session/GetUsers")
		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var users []UserRole
		db.Table("users").
			Select("users.id, users.username, users.role_id as role_id, roles.name as rolename").
			Joins("JOIN roles ON users.role_id = roles.id").
			Scan(&users)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	})

	mux.HandleFunc("POST /api/Session/AddUser", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("POST /api/Session/AddUser")
		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var userDetails UserDetails
		err := json.NewDecoder(r.Body).Decode(&userDetails)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var role Role
		db.Where("name = ?", userDetails.Rolename).Find(&role)
		if role.ID == 0 {
			db.Create(&Role{Name: userDetails.Rolename})
			db.Last(&role)
		}

		db.Create(&User{Username: userDetails.Username, Password: userDetails.Password, RoleID: role.ID})
		var user []UserRole
		db.Table("users").
			Select("users.id, users.username, users.role_id as role_id, roles.name as rolename").
			Joins("JOIN roles ON users.role_id = roles.id").
			Where("users.username = ?", userDetails.Username).
			Scan(&user)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	})

	mux.HandleFunc("DELETE /api/Session/DeleteUser/{id}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("DELETE /api/Session/DeleteUser/" + r.PathValue("id"))
		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		userID := uint(id)
		db.Delete(&User{}, userID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode("User deleted")
	})

	mux.HandleFunc("PUT /api/Session/UpdateUser/{id}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("PUT /api/Session/UpdateUser/" + r.PathValue("id"))
		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var userDetails UserDetails
		err := json.NewDecoder(r.Body).Decode(&userDetails)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var role Role
		db.Where("name = ?", userDetails.Rolename).Find(&role)
		if role.ID == 0 {
			db.Create(&Role{Name: userDetails.Rolename})
			db.Last(&role)
		}

		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		userID := uint(id)
		db.Model(&User{}).Where("id = ?", userID).Updates(User{Username: userDetails.Username, Password: userDetails.Password, RoleID: role.ID})
		var user []UserRole
		db.Table("users").
			Select("users.id, users.username, users.role_id as role_id, roles.name as rolename").
			Joins("JOIN roles ON users.role_id = roles.id").
			Where("users.id = ?", userID).
			Scan(&user)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	})
}

func verifySession(token string) bool {
	for _, session := range SessionList {
		if session.Token == token {
			return !session.ValidUntil.Before(time.Now())
		}
	}
	return false
}

func verifyRole(token string, roles []string) bool {

	var UserSession UserSession

	db.Table("sessions").
		Select("sessions.token, users.username, roles.name").
		Joins("JOIN users ON sessions.user_id = users.id").
		Joins("JOIN roles ON users.role_id = roles.id").
		Where("sessions.token = ?", token).
		Scan(&UserSession)

	for _, role := range roles {
		if UserSession.Name == role {
			return true
		}
	}

	return false
}

func muxHandleEmployeesAPI(mux *http.ServeMux) {

	mux.HandleFunc("GET /api/Employee/ping", func(w http.ResponseWriter, r *http.Request) {

		token := r.Header.Get("Authorization")
		if !verifySession(token) {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		fmt.Println("GET /api/Employee/ping")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode("Pong")
	})

	mux.HandleFunc("GET /api/Employee/GetAll", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !verifySession(token) {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}
		fmt.Println("GET /api/Employee/GetAll")
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EmployeeList)
	})

	mux.HandleFunc("GET /api/Employee/{id}", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Manager", "Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// only managers and admins can update
		fmt.Println("GET /api/Employee/" + r.PathValue("id"))
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		empID := uint(id)
		for _, emp := range EmployeeList {
			if emp.ID == empID {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(emp)
				return
			}
		}
		http.Error(w, "Employee not found", http.StatusNotFound)
	})
	mux.HandleFunc("POST /api/Employee/Add", func(w http.ResponseWriter, r *http.Request) {

		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Manager", "Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		fmt.Println("POST /api/Employee/Add")
		var employee Employee
		err := json.NewDecoder(r.Body).Decode(&employee)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		db.Create(&employee)
		db.Last(&employee)
		EmployeeList = append(EmployeeList, employee)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(employee)
	})
	mux.HandleFunc("DELETE /api/Employee/Delete/{id}", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Manager", "Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		fmt.Println("DELETE /api/Employee/Delete/" + r.PathValue("id"))
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		empID := uint(id)
		for i, emp := range EmployeeList {
			if emp.ID == empID {
				EmployeeList = append(EmployeeList[:i], EmployeeList[i+1:]...)
				break
			}
		}
		for i, task := range TaskList {
			if task.EmployeeID == empID {
				TaskList[i].EmployeeID = 0
			}
		}
		db.Delete(&Employee{}, empID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EmployeeList)
	})

	mux.HandleFunc("PUT /api/Employee/Update/{id}", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Manager", "Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		fmt.Println("PUT /api/Employee/Update/" + r.PathValue("id"))
		var employee Employee
		err := json.NewDecoder(r.Body).Decode(&employee)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		empID := uint(id)
		for i, emp := range EmployeeList {
			if emp.ID == empID {
				EmployeeList[i] = employee
				break
			}
		}
		db.Save(&employee)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(employee)
	})
}

func muxHandleTasksAPI(mux *http.ServeMux) {

	mux.HandleFunc("GET /api/Task/GetAll", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !verifySession(token) {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}
		fmt.Println("GET /api/Task/GetAll")
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TaskList)
	})

	mux.HandleFunc("GET /api/Task/{id}", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !verifySession(token) {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}
		fmt.Println("GET /api/Task/" + r.PathValue("id"))
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		taskID := uint(id)
		for _, task := range TaskList {
			if task.ID == taskID {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(task)
				return
			}
		}
		http.Error(w, "Task not found", http.StatusNotFound)

	})
	mux.HandleFunc("POST /api/Task/Add", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Manager", "Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Println("POST /api/Task/Add")
		var task Task
		err := json.NewDecoder(r.Body).Decode(&task)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		db.Create(&task)
		db.Last(&task)
		TaskList = append(TaskList, task)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(task)

	})
	mux.HandleFunc("DELETE /api/Task/Delete/{id}", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Manager", "Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		fmt.Println("DELETE /api/Task/Delete/" + r.PathValue("id"))
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		taskID := uint(id)
		for i, task := range TaskList {
			if task.ID == taskID {
				TaskList = append(TaskList[:i], TaskList[i+1:]...)
				break
			}
		}
		db.Delete(&Task{}, taskID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TaskList)

	})

	mux.HandleFunc("PUT /api/Task/Update/{id}", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !verifyRole(token, []string{"Manager", "Admin"}) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Println("PUT /api/Task/Update/" + r.PathValue("id"))
		var task Task
		err := json.NewDecoder(r.Body).Decode(&task)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		taskID := uint(id)
		for i, task := range TaskList {
			if task.ID == taskID {
				TaskList[i] = task
				break
			}
		}
		db.Save(&task)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(task)

	})
}

func main() {

	mux := http.NewServeMux()

	muxHandleSessionsAPI(mux)

	muxHandleEmployeesAPI(mux)

	muxHandleTasksAPI(mux)

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:5173"},
		AllowedHeaders: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"},
	})

	handler := c.Handler(mux)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}
