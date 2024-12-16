#!/usr/bin/env python3
import subprocess
import time

def run_test(loss_rate):
    print(f"\n{'='*50}")
    print(f"テスト実行: loss_rate = {loss_rate}")
    print(f"{'='*50}\n")

    cmd = ['python3', 'scenario14a.py', '--loss_rate', str(loss_rate)]
    process = subprocess.run(cmd, capture_output=True, text=True)

    # 結果の解析と表示
    output_lines = process.stdout.split('\n')
    for line in output_lines:
        if 'Average Delay' in line or 'Lost Packets' in line or 'cwnd' in line:
            print(line.strip())

    print(f"\n{'='*50}")
    print(f"テスト完了: loss_rate = {loss_rate}")
    print(f"{'='*50}\n")
    time.sleep(1)  # テスト間の間隔

def main():
    test_cases = [0.0, 0.05, 0.1]
    for loss_rate in test_cases:
        run_test(loss_rate)

if __name__ == '__main__':
    main()
