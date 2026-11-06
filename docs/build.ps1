<#
.SYNOPSIS
    Compila el informe LaTeX (informe.tex) a PDF.
.DESCRIPTION
    Detecta automaticamente un motor de LaTeX disponible (pdflatex,
    xelatex, lualatex o latexmk), compila el informe y limpia los archivos
    auxiliares. Se ejecuta LaTeX dos veces para resolver las referencias
    cruzadas.
.PARAMETER Engine
    Motor a usar: auto (por defecto), pdflatex, xelatex, lualatex o latexmk.
.PARAMETER Clean
    Solo elimina los archivos auxiliares generados, sin compilar.
.PARAMETER KeepAux
    No borra los archivos auxiliares luego de compilar.
.EXAMPLE
    .\build.ps1
.EXAMPLE
    .\build.ps1 -Engine pdflatex
.EXAMPLE
    .\build.ps1 -Clean
#>
[CmdletBinding()]
param(
    [ValidateSet('auto', 'latexmk', 'pdflatex', 'xelatex', 'lualatex')]
    [string]$Engine = 'auto',
    [switch]$Clean,
    [switch]$KeepAux
)

$ErrorActionPreference = 'Stop'

# Directorio del script (docs) y archivo fuente.
$DocDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$TexFile = 'informe.tex'
$PdfFile = 'informe.pdf'

# Extensiones de archivos auxiliares que genera LaTeX.
$AuxExtensions = @(
    '.aux', '.log', '.toc', '.out', '.fls', '.fdb_latexmk',
    '.synctex.gz', '.bbl', '.blg', '.nav', '.snm', '.vrb'
)

function Remove-AuxFiles {
    $removed = 0
    foreach ($ext in $AuxExtensions) {
        $path = Join-Path $DocDir ($PdfFile -replace '\.pdf$', $ext)
        if (Test-Path $path) {
            Remove-Item $path -Force
            $removed++
        }
    }
    return $removed
}

function Find-Engine {
    param([string]$Requested)
    $candidates = if ($Requested -eq 'auto') {
        @('pdflatex', 'xelatex', 'lualatex', 'latexmk')
    } else {
        @($Requested)
    }
    foreach ($name in $candidates) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        # latexmk.exe en Windows (MiKTeX) es un wrapper que necesita Perl.
        if ($name -eq 'latexmk' -and -not (Get-Command 'perl' -ErrorAction SilentlyContinue)) {
            Write-Host "Aviso: se encontro latexmk pero falta 'perl' (requerido por MiKTeX)." -ForegroundColor Yellow
            continue
        }
        return $cmd
    }
    return $null
}

# --- Caso: solo limpieza ---
if ($Clean) {
    $n = Remove-AuxFiles
    Write-Host "Limpieza completa: $n archivo(s) auxiliar(es) eliminado(s)." -ForegroundColor Green
    return
}

# --- Verificar el archivo fuente ---
$texPath = Join-Path $DocDir $TexFile
if (-not (Test-Path $texPath)) {
    Write-Error "No se encontro $TexFile en $DocDir"
    exit 1
}

# --- Buscar motor de LaTeX ---
$engineCmd = Find-Engine -Requested $Engine
if (-not $engineCmd) {
    Write-Host "ERROR: no se encontro ningun motor de LaTeX en el PATH." -ForegroundColor Red
    Write-Host ""
    Write-Host "Instala una distribucion de LaTeX, por ejemplo:" -ForegroundColor Yellow
    Write-Host "  - MiKTeX (Windows):   https://miktex.org/download"
    Write-Host "  - TeX Live (Linux):   sudo apt-get install texlive-latex-recommended texlive-latex-extra texlive-lang-spanish"
    exit 1
}

# --- Verificar que el PDF no este abierto en otro programa ---
$pdfPath = Join-Path $DocDir $PdfFile
if (Test-Path $pdfPath) {
    try {
        $stream = [System.IO.File]::Open($pdfPath, 'Open', 'ReadWrite', 'None')
        $stream.Close()
    }
    catch {
        Write-Host "ERROR: $PdfFile esta abierto en otro programa (por ejemplo un visor de PDF)." -ForegroundColor Red
        Write-Host "Cerralo y volve a ejecutar el script." -ForegroundColor Yellow
        exit 1
    }
}

$engineName = $engineCmd.Name
Write-Host "Compilando $TexFile con $engineName ..." -ForegroundColor Cyan
Push-Location $DocDir
try {
    if ($engineName -eq 'latexmk') {
        & latexmk -pdf -interaction=nonstopmode -halt-on-error $TexFile
        $exitCode = $LASTEXITCODE
    }
    else {
        # Dos pasadas para resolver referencias cruzadas.
        foreach ($pass in 1..2) {
            Write-Host "  Pasada $pass/2 ($engineName) ..." -ForegroundColor DarkGray
            & $engineName -interaction=nonstopmode -halt-on-error $TexFile
            $exitCode = $LASTEXITCODE
            if ($exitCode -ne 0) { break }
        }
    }
    if ($exitCode -ne 0) {
        Write-Host "ERROR: la compilacion fallo (codigo $exitCode)." -ForegroundColor Red
        $logPath = Join-Path $DocDir ($PdfFile -replace '\.pdf$', '.log')
        if (Test-Path $logPath) {
            Write-Host "Ver $logPath para mas detalle." -ForegroundColor Yellow
            Select-String -Path $logPath -Pattern '^!' -Context 0, 3 |
                Select-Object -First 20 |
                ForEach-Object { Write-Host $_.Line -ForegroundColor Red }
        }
        exit $exitCode
    }
}
finally {
    Pop-Location
}

# --- Borrar auxiliares ---
if (-not $KeepAux) {
    Remove-AuxFiles | Out-Null
}

# --- Verificar el PDF ---
if (Test-Path $pdfPath) {
    $size = [math]::Round((Get-Item $pdfPath).Length / 1KB, 1)
    Write-Host "OK: generado $PdfFile ($size KB)" -ForegroundColor Green
}
else {
    Write-Error "La compilacion termino sin error pero no se genero $PdfFile"
    exit 1
}
