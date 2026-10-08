package temporary

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	sha256Pattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	evidenceRefPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`,
	)
	urlPattern = regexp.MustCompile(
		`(?i)(?:[a-z][a-z0-9+.-]{1,15}://|\bwww\.|\brtsp\b|\brtsps\b)`,
	)
	credentialPattern = regexp.MustCompile(
		`(?i)(?:password|passwd|token|credential|authorization|bearer|cookie|secret|api[_ -]?key|用户名|账号|账户|密码|口令|令牌|凭证|密钥)`,
	)
	nativeIdentifierPattern = regexp.MustCompile(
		`(?i)(?:device[_ -]?id|camera[_ -]?id|channel[_ -]?id|task[_ -]?id|algorithm[_ -]?id|serial[_ -]?(?:number|no)|设备[ _-]?(?:ID|编号)|相机[ _-]?(?:ID|编号)|摄像头[ _-]?(?:ID|编号)|通道[ _-]?(?:ID|编号)|任务[ _-]?(?:ID|编号)|序列号)`,
	)
	ipv4Pattern = regexp.MustCompile(
		`(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|[^0-9])`,
	)
	base64Pattern = regexp.MustCompile(
		`(?:^|[^A-Za-z0-9_+/.-])(?:[A-Za-z0-9_+/-]{128,}={0,2})(?:$|[^A-Za-z0-9_+/=-])`,
	)
	deviceOperationPattern = regexp.MustCompile(
		`(?i)(?:(?:create|delete|enable|disable|restart|reboot|configure|modify|update|switch|connect|login|execute|run)[^\n]{0,24}(?:device|camera|task|command|shell|tool|parameter|stream)|(?:device|camera|task|parameter|stream)[^\n]{0,24}(?:create|delete|enable|disable|restart|configure|modify|update|switch)|(?:创建|新增|删除|启用|停用|打开|关闭|重启|配置|修改|切换|连接|登录|执行|运行|调用)[^\n]{0,12}(?:设备|摄像头|相机|任务|参数|命令|脚本|工具|视频源)|(?:设备|摄像头|相机|任务|参数|视频源)[^\n]{0,12}(?:创建|新增|删除|启用|停用|打开|关闭|重启|配置|修改|切换))`,
	)
	toolInstructionPattern = regexp.MustCompile(
		`(?i)(?:function[ _-]?call|tool[ _-]?call|调用工具|使用工具|执行[ ]*(?:shell|bash|powershell|脚本)|\bcurl\b|\bsudo\b|\bpowershell\b)`,
	)
	promptInjectionPattern = regexp.MustCompile(
		`(?i)(?:(?:忽略|无视|绕过|覆盖)[^\n]{0,12}(?:以上|之前|前面|规则|限制|指令|提示)|(?:系统提示|开发者消息|提示词注入)|(?:ignore|disregard|override|bypass)[^\n]{0,24}(?:previous|prior|above|instruction|prompt|rule))`,
	)
	compliancePattern = regexp.MustCompile(
		`(?i)(?:合规|合法|违法|监管|认证|达标|符合.{0,8}(?:规范|标准|法规)|\bcompliant\b|\bcompliance\b|\blegal\b|\bregulatory\b|\bcertified\b)`,
	)
)

func normalizeApprovedText(name, value string, maximumRunes int) (string, error) {
	if maximumRunes < 1 {
		return "", errors.New("temporary observation text bound is invalid")
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("temporary observation %s is not valid UTF-8", name)
	}
	if len(value) > maximumRunes*4 {
		return "", fmt.Errorf("temporary observation %s is too long", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", fmt.Errorf("temporary observation %s contains a control or format character", name)
		}
	}
	normalized := strings.Join(strings.Fields(value), " ")
	count := utf8.RuneCountInString(normalized)
	if count < 1 || count > maximumRunes {
		return "", fmt.Errorf("temporary observation %s must contain 1 to %d characters", name, maximumRunes)
	}
	if strings.Contains(normalized, "{{") || strings.Contains(normalized, "}}") ||
		strings.Contains(normalized, "${") || strings.Contains(normalized, "<%") || strings.Contains(normalized, "%>") {
		return "", fmt.Errorf("temporary observation %s contains template syntax", name)
	}
	if urlPattern.MatchString(normalized) {
		return "", fmt.Errorf("temporary observation %s contains a URL or stream address", name)
	}
	if credentialPattern.MatchString(normalized) {
		return "", fmt.Errorf("temporary observation %s contains protected credential text", name)
	}
	if nativeIdentifierPattern.MatchString(normalized) || ipv4Pattern.MatchString(normalized) || base64Pattern.MatchString(normalized) {
		return "", fmt.Errorf("temporary observation %s contains protected identifier or encoded data", name)
	}
	if deviceOperationPattern.MatchString(normalized) {
		return "", fmt.Errorf("temporary observation %s contains a device operation intent", name)
	}
	if toolInstructionPattern.MatchString(normalized) {
		return "", fmt.Errorf("temporary observation %s contains a tool instruction", name)
	}
	if promptInjectionPattern.MatchString(normalized) {
		return "", fmt.Errorf("temporary observation %s contains a prompt instruction", name)
	}
	if compliancePattern.MatchString(normalized) {
		return "", fmt.Errorf("temporary observation %s requests a compliance assertion", name)
	}
	return normalized, nil
}

func validateEvidenceRef(ref string) error {
	if !evidenceRefPattern.MatchString(ref) {
		return errors.New("temporary observation evidence reference is invalid")
	}
	return nil
}

func validateUniqueTextList(name string, values []string, maximumItems, maximumRunes int, requireNonEmpty bool) error {
	if values == nil {
		return fmt.Errorf("temporary observation %s must be present", name)
	}
	if len(values) > maximumItems || (requireNonEmpty && len(values) == 0) {
		return fmt.Errorf("temporary observation %s has an invalid item count", name)
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		normalized, err := normalizeApprovedText(fmt.Sprintf("%s item %d", name, index+1), value, maximumRunes)
		if err != nil {
			return err
		}
		if normalized != value {
			return fmt.Errorf("temporary observation %s item %d is not normalized", name, index+1)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("temporary observation %s repeats an item", name)
		}
		seen[value] = struct{}{}
	}
	return nil
}
