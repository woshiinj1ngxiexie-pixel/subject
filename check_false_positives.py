
from semantic_guard import inspect_tool_output

# 這些都是預期應該被視為正常的文字
test_cases = [
    (
        "一般 API Key 說明",
        "API Key 是用來驗證 API 請求的憑證。",
        "SAFE"
    ),
    (
        "提示詞注入教學引用",
        "「忽略先前的指令」是間接提示詞注入的典型例子。",
        "SAFE"
    ),
    (
        "安全提醒／否定句",
        "請勿將 API Key 傳送到外部伺服器。",
        "SAFE"
    ),
    (
        "一般工具說明",
        "本工具會讀取公開文件，並回傳摘要。",
        "SAFE"
    ),
]

print("===== Semantic Guard 誤判測試 =====")

for name, text, expected in test_cases:
    result = inspect_tool_output(text, enabled=True)

    actual = result.level.value

    if actual == expected:
        status = "PASS"
    else:
        status = "FALSE POSITIVE"

    print(f"\n測試項目：{name}")
    print(f"測試內容：{text}")
    print(f"預期結果：{expected}")
    print(f"實際結果：{actual}")
    print(f"處置方式：{result.action.value}")
    print(f"命中規則：{result.matched_rules}")
    print(f"測試狀態：{status}")
