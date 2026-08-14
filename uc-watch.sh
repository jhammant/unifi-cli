#!/bin/bash
# uc-watch — capture everything needed to explain a Universal Control dropout.
#
# Two streams into ~/uc-watch/:
#   events.log    live log stream from every subsystem involved
#   state.tsv     a state snapshot every 15s, so we can see what changed and when
#
# When the peer Mac disappears from the Displays panel, note the time and
# correlate against these. Stop with:  pkill -f uc-watch

OUT="$HOME/uc-watch"
mkdir -p "$OUT"

# --- rich event stream -------------------------------------------------------
/usr/bin/log stream --style compact \
  --predicate 'process == "rapportd" OR process == "UniversalControl" OR process == "sharingd" OR process == "bluetoothd"' \
  >> "$OUT/events.log" 2>/dev/null &
STREAM_PID=$!

cleanup() { kill "$STREAM_PID" 2>/dev/null; exit 0; }
trap cleanup INT TERM

# --- periodic state snapshot -------------------------------------------------
if [ ! -s "$OUT/state.tsv" ]; then
  printf 'time\tch\trssi\tphy\tawdl\tadv_starts\tadv_stops\tpeer_found\tpeer_lost\n' > "$OUT/state.tsv"
fi

while true; do
  TS=$(date '+%Y-%m-%d %H:%M:%S')

  # NEVER use `system_profiler SPAirPortDataType` here. It forces a 25-channel
  # ACTIVE scan lasting ~20s, taking the radio off channel and starving AWDL/BLE
  # — i.e. it causes the exact dropout this script exists to observe. Learned the
  # hard way on 2026-08-13: polling it every 15s produced ~96 scans/hour on a
  # machine that had none. `ipconfig getsummary` reads cached state, no scan.
  WIFI=$(ipconfig getsummary en0 2>/dev/null)
  CH=$(printf '%s' "$WIFI"   | awk -F': ' '/Channel/{print $2; exit}' | tr -d ' ')
  RSSI=$(printf '%s' "$WIFI" | awk -F': ' '/RSSI/{print $2; exit}' | tr -d ' ')
  PHY=$(printf '%s' "$WIFI"  | awk -F': ' '/LinkStatusActive/{print $2; exit}' | tr -d ' ')
  AWDL=$(ifconfig awdl0 2>/dev/null | awk '/status:/{print $2}')

  # last 60s of advertising / peer churn
  W=$(/usr/bin/log show --last 60s --predicate 'process == "rapportd"' --style compact 2>/dev/null)
  ADV_START=$(printf '%s' "$W" | grep -c 'Start advertise')
  ADV_STOP=$(printf '%s'  "$W" | grep -c 'Stop advertise')

  U=$(/usr/bin/log show --last 60s --predicate 'process == "UniversalControl"' --style compact 2>/dev/null)
  P_FOUND=$(printf '%s' "$U" | grep -c 'Device Found')
  P_LOST=$(printf '%s'  "$U" | grep -c 'Device Lost')

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$TS" "${CH:--}" "${RSSI:--}" "${PHY:--}" "${AWDL:--}" \
    "$ADV_START" "$ADV_STOP" "$P_FOUND" "$P_LOST" >> "$OUT/state.tsv"

  sleep 15
done
