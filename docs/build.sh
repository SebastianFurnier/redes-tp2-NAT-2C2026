#!/usr/bin/env bash
#
# build.sh - Compila el informe LaTeX (informe.tex) a PDF.
#
# Uso:
#   ./build.sh                 # detecta el motor y compila
#   ./build.sh pdflatex        # fuerza un motor: latexmk|pdflatex|xelatex|lualatex
#   ./build.sh --clean         # solo borra archivos auxiliares
#   ./build.sh --keep-aux      # no borra los auxiliares tras compilar
#
set -euo pipefail
DOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEX_FILE="informe.tex"
PDF_FILE="informe.pdf"
ENGINE="auto"
CLEAN_ONLY=0
KEEP_AUX=0

# --- Parseo de argumentos ---
for arg in "$@"; do
  case "$arg" in
    --clean)    CLEAN_ONLY=1 ;;
    --keep-aux) KEEP_AUX=1 ;;
    latexmk|pdflatex|xelatex|lualatex) ENGINE="$arg" ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Argumento desconocido: $arg" >&2
      exit 2
      ;;
  esac
done

AUX_EXTENSIONS=(aux log toc out fls fdb_latexmk synctex.gz bbl blg nav snm vrb)
clean_aux() {
  local removed=0
  for ext in "${AUX_EXTENSIONS[@]}"; do
    local f="$DOC_DIR/informe.$ext"
    if [ -f "$f" ]; then
      rm -f "$f"
      removed=$((removed + 1))
    fi
  done
  echo "Limpieza completa: $removed archivo(s) auxiliar(es) eliminado(s)."
}

# --- Caso: solo limpieza ---
if [ "$CLEAN_ONLY" -eq 1 ]; then
  clean_aux
  exit 0
fi

# --- Verificar el archivo fuente ---
if [ ! -f "$DOC_DIR/$TEX_FILE" ]; then
  echo "ERROR: no se encontro $TEX_FILE en $DOC_DIR" >&2
  exit 1
fi

# --- Buscar motor de LaTeX ---
if [ "$ENGINE" = "auto" ]; then
  for candidate in pdflatex xelatex lualatex latexmk; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if [ "$candidate" = "latexmk" ] && ! command -v perl >/dev/null 2>&1; then
        echo "Aviso: se encontro latexmk pero falta 'perl' (requerido por MiKTeX)." >&2
        continue
      fi
      ENGINE="$candidate"
      break
    fi
  done
fi

if ! command -v "$ENGINE" >/dev/null 2>&1; then
  echo "ERROR: no se encontro el motor de LaTeX '$ENGINE' en el PATH." >&2
  echo ""
  echo "Instala una distribucion de LaTeX, por ejemplo:"
  echo "  - TeX Live (Linux):  sudo apt-get install texlive-latex-recommended texlive-latex-extra texlive-lang-spanish"
  echo "  - MiKTeX (Windows):  https://miktex.org/download"
  exit 1
fi

echo "Compilando $TEX_FILE con $ENGINE ..."
cd "$DOC_DIR"
if [ "$ENGINE" = "latexmk" ]; then
  latexmk -pdf -interaction=nonstopmode -halt-on-error "$TEX_FILE"
else
  # Dos pasadas para resolver referencias cruzadas.
  for pass in 1 2; do
    echo "  Pasada $pass/2 ($ENGINE) ..."
    "$ENGINE" -interaction=nonstopmode -halt-on-error "$TEX_FILE"
  done
fi

# --- Borrar auxiliares ---
if [ "$KEEP_AUX" -eq 0 ]; then
  clean_aux >/dev/null
fi

# --- Verificar el PDF ---
if [ -f "$DOC_DIR/$PDF_FILE" ]; then
  size=$(du -k "$DOC_DIR/$PDF_FILE" | cut -f1)
  echo "OK: generado $PDF_FILE (${size} KB)"
else
  echo "ERROR: la compilacion no genero $PDF_FILE" >&2
  exit 1
fi
