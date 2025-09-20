#!/usr/bin/env bash
TARGET=100.124.205.73
PORT=5020
OUTDIR=./mbt_device_reg_coil_scan
mkdir -p "$OUTDIR"

# 設備範圍 1~50
for unit in $(seq 1 50); do
  echo "===== Scanning device unit=$unit =====" | tee -a "$OUTDIR/results.txt"

  # 掃描 register 範圍 40001~40100
  for addr in $(seq 40001 40100); do
    echo "Reading unit=$unit register=$addr" | tee -a "$OUTDIR/results.txt"
    mbtget -d -r3 -a "$addr" -n 1 -f -u "$unit" -p "$PORT" "$TARGET" \
      >> "$OUTDIR/results.txt" 2>&1
    echo "----" >> "$OUTDIR/results.txt"
  done

  # 掃描 coil 範圍 1~50
  for coil in $(seq 1 50); do
    echo "Reading unit=$unit coil=$coil" | tee -a "$OUTDIR/results.txt"
    mbtget -d -r1 -a "$coil" -n 1 -f -u "$unit" -p "$PORT" "$TARGET" \
      >> "$OUTDIR/results.txt" 2>&1
    echo "----" >> "$OUTDIR/results.txt"
  done

done
