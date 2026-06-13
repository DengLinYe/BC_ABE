module bc_abe/abe

go 1.25.0

require bc_abe v0.0.0

require bc_abe/utils v0.0.0

require (
	github.com/antlr/antlr4/runtime/Go/antlr v0.0.0-20211106181442-e4c1a74c66bd // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/sys v0.40.0 // indirect
)

replace bc_abe => ../

replace bc_abe/utils => ../utils
