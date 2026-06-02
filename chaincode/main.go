package main

import (
	"fmt"
	"os"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	chaincode, err := contractapi.NewChaincode(new(ABELedger))
	if err != nil {
		fmt.Fprintf(os.Stderr, "create chaincode: %v\n", err)
		os.Exit(1)
	}
	if err := chaincode.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start chaincode: %v\n", err)
		os.Exit(1)
	}
}
