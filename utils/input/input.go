package input

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func Ask(q string) (string, error) {
  reader := bufio.NewReader(os.Stdin)
  fmt.Printf("%s ", q)
  text, err := reader.ReadString('\n')
  if err != nil {
    return "", err
  }
  return strings.TrimSpace(text), nil
}

