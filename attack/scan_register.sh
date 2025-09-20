#!/usr/bin/env bash
TARGET=100.124.205.73
PORT=5020
UNIT=1
START=40001
END=40100
OUTDIR=./mbt_single_scan
mkdir -p "$OUTDIR"

for addr in $(seq $START $END); do
  echo "Reading addr=$addr" | tee -a "$OUTDIR/results.txt"
  # 每次只讀 1 筆
  mbtget -d -r3 -a "$addr" -n 1 -f -u "$UNIT" -p "$PORT" "$TARGET" \
    >> "$OUTDIR/results.txt" 2>&1
  echo "----" >> "$OUTDIR/results.txt"
done
