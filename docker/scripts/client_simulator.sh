#!/bin/sh

TARGET_IP="10.0.0.10"
TARGET_HTTP="http://${TARGET_IP}:8080"

echo "Starting completely random background traffic generator..."

# User agents for HTTP requests
get_random_ua() {
  rand_ua=$((RANDOM % 4))
  case $rand_ua in
    0) echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0 Safari/537.36" ;;
    1) echo "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15" ;;
    2) echo "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15" ;;
    3) echo "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0" ;;
  esac
}

while true; do
  # Simulating a human browsing session (HTTP and DNS only)
  # Humans don't port-scan random IPs or send raw empty TCP packets!
  
  action=$((RANDOM % 3))
  
  case $action in
    0)
      # Human reads the front page
      UA=$(get_random_ua)
      echo "[Client] Browsing the front page..."
      curl -s -A "$UA" "${TARGET_HTTP}/" > /dev/null &
      
      # Humans take a long time to read a page
      sleep_time=$(( (RANDOM % 20) + 10 )) # 10 to 30 seconds
      sleep $sleep_time
      ;;
      
    1)
      # Human searches for something and clicks around
      UA=$(get_random_ua)
      echo "[Client] Searching for a product..."
      curl -s -A "$UA" "${TARGET_HTTP}/search?q=test" > /dev/null &
      
      # Takes 5-10 seconds to read the results
      sleep $(( (RANDOM % 5) + 5 ))
      
      # Clicks a result (loads dashboard)
      echo "[Client] Clicking a product link..."
      curl -s -A "$UA" "${TARGET_HTTP}/dashboard" > /dev/null &
      
      # Reads the product page
      sleep_time=$(( (RANDOM % 25) + 15 )) # 15 to 40 seconds
      sleep $sleep_time
      ;;
      
    2)
      # Human opens a new tab and goes to a popular website (DNS)
      domains="google.com youtube.com amazon.com wikipedia.org facebook.com"
      set -- $domains
      num_doms=$#
      rand_index=$(( (RANDOM % num_doms) + 1 ))
      i=1
      for dom in "$@"; do
        if [ "$i" -eq "$rand_index" ]; then selected_dom=$dom; break; fi
        i=$((i + 1))
      done
      
      echo "[Client] Opening new tab to $selected_dom..."
      nslookup $selected_dom > /dev/null 2>&1 &
      
      sleep_time=$(( (RANDOM % 10) + 5 )) # 5 to 15 seconds
      sleep $sleep_time
      ;;
  esac
done
