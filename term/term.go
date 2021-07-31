// terminal input processing

package term

import (
	"fmt"
	"os"
)

// ask a y/n question. get a boolean back
func Ask(message string) (resp bool, err error) {
	var in string
	fmt.Fprintf(os.Stderr, "%s [y/N] ", message)
	fmt.Scanf("%s", &in)

	if !(in[0] == 'y' || in[0] == 'Y') {
		return false, nil
	}

	return true, nil
}
