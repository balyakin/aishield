package exitcode

const (
	Success              = 0
	RuntimeError         = 1
	PolicyBlocked        = 2
	ConfigValidation     = 3
	ChildProcessFailed   = 4
	ConfirmationRejected = 5
)

type Error struct {
	Code    int
	Message string
}

func (err Error) Error() string {
	return err.Message
}

func New(code int, message string) Error {
	return Error{
		Code:    code,
		Message: message,
	}
}
