package main

import (
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// 设置Gin模式
	gin.SetMode(gin.ReleaseMode)

	// 创建Gin引擎
	router := gin.Default()

	// 注册路由
	registerRoutes(router)

	// 启动HTTP服务器
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // 默认端口号
	}
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Printf("Server started. Listening on port %s\n", port)

	// 启动服务器
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server startup failed: %v", err)
	}
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var users = map[string]string{
	"user1": "$2a$10$6Is3ixdwyi8E.9Ip5VqYxO0hrGf1kPYH6eJwLymVj4SE2A7F2sfSe", // 密码是 "password1"
	"user2": "$2a$10$y4fIAwQk.pZ5fH9mFmFhjeS4TFKf8p/bBB6nlspdsH6v/nwVBDDqW", // 密码是 "password2"
}

func authenticateUser(username, password string) bool {
	hashedPassword, ok := users[username]
	if !ok {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func registerRoutes(router *gin.Engine) {
	// 注册路由处理函数
	//router.GET("/", homeHandler)
	//router.GET("/articles/:id", articleHandler)
	router.POST("/articles", createArticleHandler)
	// 其他路由...
	//登陆路由
	router.POST("login", loginHandler)
	// 静态文件服务
	router.Static("/static", "./static")
	//加载html模版
	router.LoadHTMLGlob("templates/*.html")
}

//func homeHandler(c *gin.Context) {
//	articles := []Article{
//		ID:    1,
//		Title: "文章1",
//		ID:    2,
//		Title: "文章2",
//	}
//
//	c.HTML(http.StatusOK, "home.html", gin.H{
//		"Articles": articles,
//	})
//}
//func articleHandler(c *gin.Context) {
//	articleID := c.Param("id")
//	// 根据文章ID获取文章信息
//	article := Article{
//		ID:      articleID,
//		Title:   "示例文章",
//		Content: "这是一个示例文章的内容。",
//	}
//}

func createArticleHandler(c *gin.Context) {
	// 获取请求参数并创建文章
	// title := c.PostForm("title")
	// content := c.PostForm("content")
	// createArticle(title, content)
	c.JSON(http.StatusOK, gin.H{"message": "Article created"})
}

func loginHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	if authenticateUser(user.Username, user.Password) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": user.Username,
		})
		tokenString, err := token.SignedString([]byte("your-secret-key")) // 替换为你自己的密钥
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}
