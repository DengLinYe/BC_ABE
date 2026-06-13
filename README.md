启动：
主控：根目录 go run .
org1 管理端：cd auth_admin && ORG_NAME=org1 go run .
org2 管理端：cd auth_admin && ORG_NAME=org2 go run .
用户端：cd user_client && go run .
