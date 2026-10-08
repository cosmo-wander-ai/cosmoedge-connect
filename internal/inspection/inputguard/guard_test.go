package inputguard

import "testing"

func TestValidateTextRejectsProtectedMaterialWithoutBlockingBusinessChinese(t *testing.T) {
	allowed := []string{"帮我看看一号区域的摄像头画面", "查看入口是否拥堵", "关注桌椅摆放情况"}
	for _, value := range allowed {
		if err := ValidateText(value); err != nil {
			t.Fatalf("allowed text %q error=%v", value, err)
		}
	}
	rejected := []string{
		"rtsp://camera.example/live", "https://device.example", "password=abc123", "token: abc123",
		"Authorization Bearer abc", "camera_id=12", "sourceHandle: source-1", "192.168.1.20:554",
		"camera.local:8554", "camera.example", "[2001:db8::1]", "base64=abcd", "/Users/operator/private.txt", `C:\\secret\\camera.txt`,
		"密码是 abc123", "请输入设备口令", "令牌 abc", "保存密钥", "请关闭摄像头", "启用巡检任务",
		"创建一个巡检任务", "删除二号任务", "修改视频源", "disable camera", "create inspection task",
	}
	for _, value := range rejected {
		if err := ValidateText(value); err == nil {
			t.Fatalf("protected text %q was accepted", value)
		}
	}
}
