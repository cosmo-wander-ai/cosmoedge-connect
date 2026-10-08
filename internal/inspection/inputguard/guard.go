// Package inputguard rejects protected connection and credential material at
// the channel boundary. Normal business language, including Chinese words
// such as 摄像头 and 区域, is intentionally allowed.
package inputguard

import (
	"errors"
	"regexp"
	"strings"
)

var (
	uriPattern            = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])(?:https?|rtsps?|file|data):`)
	credentialPattern     = regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|token|secret|credential|authorization|cookie|api[_-]?key|access[_-]?key)\b`)
	chineseSecretPattern  = regexp.MustCompile(`(?:密码|口令|令牌|密钥|凭据|认证信息)`)
	nativeIdentityPattern = regexp.MustCompile(`(?i)\b(?:device|camera|source|stream)[_-]?(?:id|handle|endpoint|url)\s*[:=]`)
	ipv4Pattern           = regexp.MustCompile(`(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?(?:$|[^0-9])`)
	ipv6Pattern           = regexp.MustCompile(`(?i)(?:^|[\s\[])(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?:\]|$|\s)`)
	hostPortPattern       = regexp.MustCompile(`(?i)\b(?:localhost|[a-z][a-z0-9-]{1,63}|[a-z][a-z0-9.-]*\.[a-z]{2,63}):[0-9]{2,5}\b`)
	dottedHostPattern     = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
	encodedPattern        = regexp.MustCompile(`(?i)\bbase64\s*[:=]|[A-Za-z0-9+/]{160,}={0,2}`)
	unixPathPattern       = regexp.MustCompile(`(?:^|\s)/(?:Users|home|etc|var|opt|private|mnt|srv|root)/[^\s]+`)
	windowsPathPattern    = regexp.MustCompile(`(?i)(?:^|\s)[a-z]:\\[^\s]+`)
	deviceWritePattern    = regexp.MustCompile(`(?i)(?:\b(?:enable|disable|open|close|start|stop|create|delete|remove|modify|update|configure)\b.{0,24}\b(?:camera|device|task|source|stream)\b|(?:启用|禁用|关闭|打开|开启|停用|停止).{0,12}(?:摄像头|相机|设备|任务|视频源)|(?:创建|新建|删除|移除|修改|更新|部署).{0,12}(?:巡检任务|任务|摄像头|相机|设备|视频源)|(?:摄像头|相机|设备|任务|视频源).{0,8}(?:启用|禁用|关闭|打开|开启|停用|停止|删除|修改|更新))`)
)

func ValidateText(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	if uriPattern.MatchString(trimmed) || credentialPattern.MatchString(trimmed) || chineseSecretPattern.MatchString(trimmed) ||
		nativeIdentityPattern.MatchString(trimmed) || ipv4Pattern.MatchString(trimmed) || ipv6Pattern.MatchString(trimmed) ||
		hostPortPattern.MatchString(trimmed) || dottedHostPattern.MatchString(trimmed) || encodedPattern.MatchString(trimmed) ||
		unixPathPattern.MatchString(trimmed) || windowsPathPattern.MatchString(trimmed) || deviceWritePattern.MatchString(trimmed) {
		return errors.New("inspection text contains protected connection, credential, native identity, path, or device-write material")
	}
	return nil
}
