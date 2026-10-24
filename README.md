# 密碼產生器 (Password Generator)

一個免安裝的 Windows 密碼產生器，單一 exe（約 48 KB），不需要另外安裝任何執行環境。

## 下載

到本頁右側的 **Releases**，下載最新版本的 `PasswordGenerator.exe`，雙擊即可執行。

> 這個 exe 沒有數位簽章，第一次執行時 Windows 可能會跳出「Windows 已保護您的電腦」，
> 點「其他資訊」→「仍要執行」即可。
> 如果電腦開啟了「智慧型應用程式控制」(Smart App Control)，沒有簽章的程式會直接被封鎖，無法執行。

## 功能

- **密碼長度 2 ~ 99 位**：可用滑桿或直接輸入。
- **字元類型**：數字、大寫英文、小寫英文、符號，可自由勾選。
- **符號規則**：內建「預設符號」、「全部符號」、「常見網站相容」、「最保守 (!@#$)」，
  也可以直接編輯要用的符號，並存成自己的規則（例如某個網站只允許特定符號）。
- **一次產生 1 ~ 10 組**，每組都保證包含每一種勾選的字元類型。
- **複製紀錄**：記住複製過的密碼與時間，可加上備註（用在哪個網站），雙擊即可再次複製。
- **避免規律排列**：以密碼學安全亂數產生，並排除相鄰重複（`aa`、`aba`）、
  連號（`abc`、`321`）、鍵盤順序（`qwe`、`!@#`）。
- **排除易混淆字元**：`` 0 O o 1 I l | ` ' " ``。
- 即時顯示密碼強度（bits）。
- 複製的密碼不會進入 Windows 剪貼簿歷程（Win+V）與雲端同步，也可設定 30 秒後自動清除剪貼簿。

## 資料存放位置

設定與複製紀錄存在 `%APPDATA%\PasswordGenerator\`：

- `settings.ini`：介面設定與自訂符號規則（不含密碼）。
- `history.dat`：複製紀錄，以 Windows DPAPI 加密，只有同一台電腦上的同一個 Windows 帳號能解開。
  換電腦或換帳號後，舊的紀錄無法讀取。

可以在程式中取消勾選「記住複製紀錄」，紀錄就只保留到關閉程式為止。

## 自行編譯

只需要 Windows 內建的 .NET Framework 4（Windows 10 / 11 都有），在 PowerShell 執行：

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

會在同一個資料夾產生 `PasswordGenerator.exe`。

執行自我測試（產生 20,000 組密碼並逐一檢查規則，結果寫到 `%TEMP%\pwgen-selftest.txt`）：

```powershell
.\PasswordGenerator.exe --selftest
```

## 檔案結構

```
build.ps1                  編譯腳本（產生圖示並呼叫 csc.exe）
src/PasswordGenerator.cs   全部原始碼（C# WinForms）
src/app.ico                程式圖示
```
