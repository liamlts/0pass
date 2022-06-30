module example.com/0pass

go 1.18

replace example.com/cryptog => ../0pass/cryptog

require (
	example.com/cryptog v0.0.0-00010101000000-000000000000
	github.com/urfave/cli v1.22.5
	golang.org/x/term v0.0.0-20220526004731-065cf7ba2467
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.0-20190314233015-f79a8a8ca69d // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20220331220935-ae2d96664a29 // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
)
