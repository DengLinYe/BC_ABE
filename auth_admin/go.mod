module bc_abe_aa

go 1.25.0

require (
	bc_abe/abe v0.0.0
	bc_abe/utils v0.0.0
)

require (
	bc_abe v0.0.0 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr v0.0.0-20211106181442-e4c1a74c66bd // indirect
	github.com/go-sql-driver/mysql v1.8.1 // indirect
	github.com/hyperledger/fabric-gateway v1.11.0 // indirect
	github.com/hyperledger/fabric-protos-go-apiv2 v0.3.7 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/grpc v1.80.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gorm.io/driver/mysql v1.6.0 // indirect
	gorm.io/gorm v1.30.0 // indirect
)

replace (
	bc_abe => ../
	bc_abe/abe => ../abe
	bc_abe/utils => ../utils
)
