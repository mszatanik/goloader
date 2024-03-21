package colors

import "log"

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
)

func Fatal(msg string) {
	log.Fatalf("%s[-] %s%s\r\n", Red, msg, Reset)
}

func Info(msg string) {
	log.Printf("%s[*] %s%s\r\n", Yellow, msg, Reset)
}

func Ok(msg string) {
	log.Printf("%s[+] %s%s\r\n", Green, msg, Reset)
}
