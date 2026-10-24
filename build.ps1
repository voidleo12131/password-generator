# 編譯密碼產生器 (使用 Windows 內建的 .NET Framework 4 C# 編譯器，不需另外安裝)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$src  = Join-Path $root 'src\PasswordGenerator.cs'
$ico  = Join-Path $root 'src\app.ico'
$out  = Join-Path $root 'PasswordGenerator.exe'
$csc  = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }

# 產生程式圖示 (多尺寸 PNG 格式的 .ico)
if (-not (Test-Path $ico)) {
    Add-Type -AssemblyName System.Drawing
    $sizes = 16, 24, 32, 48, 256
    $pngs = foreach ($s in $sizes) {
        $bmp = New-Object System.Drawing.Bitmap $s, $s
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = 'AntiAlias'
        $g.Clear([System.Drawing.Color]::Transparent)
        $k = $s / 256.0
        # 以 256x256 為基準座標，換算成目前尺寸 (GDI+ 需要 float 參數)
        function S([double]$v) { [float]($v * $k) }
        # 圓角背景
        $path = New-Object System.Drawing.Drawing2D.GraphicsPath
        $r = S 56; $w = [float]($s - 1); $z = [float]0
        $path.AddArc($z, $z, $r, $r, [float]180, [float]90); $path.AddArc($w - $r, $z, $r, $r, [float]270, [float]90)
        $path.AddArc($w - $r, $w - $r, $r, $r, $z, [float]90); $path.AddArc($z, $w - $r, $r, $r, [float]90, [float]90)
        $path.CloseFigure()
        $rect = New-Object System.Drawing.Rectangle 0, 0, $s, $s
        $brush = [System.Drawing.Drawing2D.LinearGradientBrush]::new($rect, [System.Drawing.Color]::FromArgb(52, 120, 246), [System.Drawing.Color]::FromArgb(24, 64, 170), [float]90)
        $g.FillPath($brush, $path)
        # 鎖頭: 鎖環 + 鎖身 + 鑰匙孔
        $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::White, [float][Math]::Max(2, 22 * $k))
        $g.DrawArc($pen, (S 84), (S 44), (S 88), (S 96), [float]180, [float]180)
        $g.DrawLine($pen, (S 84), (S 92), (S 84), (S 120))
        $g.DrawLine($pen, (S 172), (S 92), (S 172), (S 120))
        $g.FillRectangle([System.Drawing.Brushes]::White, (S 58), (S 116), (S 140), (S 100))
        if ($s -ge 32) {
            $hole = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(24, 64, 170))
            $g.FillEllipse($hole, (S 112), (S 138), (S 32), (S 32))
            $g.FillRectangle($hole, (S 121), (S 160), (S 14), (S 34))
        }
        $g.Dispose()
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
        , $ms.ToArray()
    }
    $fs = [System.IO.File]::Create($ico)
    $bw = New-Object System.IO.BinaryWriter $fs
    $bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $d = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
        $bw.Write([byte]$d); $bw.Write([byte]$d); $bw.Write([byte]0); $bw.Write([byte]0)
        $bw.Write([UInt16]1); $bw.Write([UInt16]32)
        $bw.Write([UInt32]$pngs[$i].Length); $bw.Write([UInt32]$offset)
        $offset += $pngs[$i].Length
    }
    foreach ($p in $pngs) { $bw.Write($p) }
    $bw.Close()
}

& $csc /nologo /target:winexe /optimize+ /codepage:65001 /win32icon:"$ico" /out:"$out" `
    /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Security.dll `
    "$src"
if ($LASTEXITCODE -ne 0) { throw "編譯失敗" }
Write-Host "完成: $out"
