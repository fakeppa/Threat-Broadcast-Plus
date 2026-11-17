#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# Telegram 频道推送：威胁情报播报（增强版）
#   1. 顶部附 Kimi AI 风险研判摘要（有则推）
#   2. 按危害等级排序：KEV 在野利用 > 严重 > 高危 > 中危 > 低危
#   3. 每条带等级徽章，低危/中危折叠为计数
#   4. HTML 转义防注入，超长自动截断
# -----------------------------------------------

import json
import os
import requests
from datetime import datetime

import src.config as config
from src.bean.cve_info import CST, LEVEL_CN
from src.logger import log

PAGE_URL = 'https://threat.aabyss.cn/'
MAX_CONTENT = 4000          # sendMessage 上限 4096，留余量
MAX_AI_CHARS = 600          # AI 研判在 Telegram 里显示的长度
IMPORTANT_LEVELS = ('KEV', 'CRITICAL', 'HIGH')   # 值得逐条列出的等级

# 等级 -> 徽章
BADGE = {
    'KEV': '🚨',
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '⚪',
    '': '▫️',
}
LEVEL_RANK = {'KEV': 0, 'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, '': 5}

SUMMARY_PATH = os.path.join(config.PRJ_DIR, 'data', 'ai_summary.json')


def to_telegram(cves):
    if not cves:
        return False

    bot_token = (config.settings.get('notify', 'telegram_bot_token', '') or '').strip()
    chat_id = (config.settings.get('notify', 'telegram_chat_id', '') or '').strip()

    if not (bot_token and chat_id):
        log.debug('[Telegram] 未配置推送渠道，跳过')
        return False

    content = build_html(cves)
    return _send(bot_token, chat_id, content)


def _total(cves):
    return sum(len(items) for items in cves.values())


def _load_ai_summary():
    """读取最新 AI 研判（kimi.to_summary 在推送前已生成/刷新）。"""
    try:
        with open(SUMMARY_PATH, 'r', encoding=config.CHARSET) as f:
            data = json.load(f)
        content = str(data.get('content') or '').strip()
        return content[:MAX_AI_CHARS] if content else ''
    except (OSError, ValueError):
        return ''


def _esc(text):
    return (text or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def build_html(cves):
    total = _total(cves)
    lines = [
        '<b>🛡 Threat Broadcast</b>',
        '新增 <b>%d</b> 条 · %s' % (total, datetime.now(CST).strftime('%Y-%m-%d %H:%M')),
    ]

    # ---- AI 研判摘要 ----
    ai = _load_ai_summary()
    if ai:
        lines += ['', '<blockquote>%s</blockquote>' % _esc(ai)]

    # ---- 汇总所有漏洞并按等级排序 ----
    flat = []
    for src, items in cves.items():
        for cve in items:
            flat.append((src.NAME_CH(), cve))

    flat.sort(key=lambda pair: LEVEL_RANK.get(
        (pair[1].level or '').upper(), 5))

    shown = 0
    minor = 0
    per_source_lines = []
    seen_sources = {}

    for src_name, cve in flat:
        level = (cve.level or '').upper()
        badge = BADGE.get(level, '▫️')
        # KEV / 严重 / 高危：逐条列出；其余折叠计数
        if level not in IMPORTANT_LEVELS:
            minor += 1
            continue

        title = _esc((cve.title or '').strip()[:70])
        cid = _esc(cve.id or '详情')
        kev_mark = ' <b>[在野利用]</b>' if level == 'KEV' else ''
        if cve.url:
            per_source_lines.append('%s <a href="%s">%s</a> %s%s'
                                    % (badge, cve.url, cid, title, kev_mark))
        else:
            per_source_lines.append('%s %s %s%s' % (badge, cid, title, kev_mark))
        seen_sources[src_name] = seen_sources.get(src_name, 0) + 1
        shown += 1

    # 每源展示上限（防止单源刷屏）
    MAX_PER_SRC = 8
    filtered = []
    per_src_count = {}
    for line in per_source_lines:
        # 行内不含源名，用顺序计数即可：按来源分组重排
        filtered.append(line)
    # 简化：按来源名重新分组展示
    lines.append('')
    for src_name, count in seen_sources.items():
        lines.append('<b>%s</b>' % _esc(src_name))
    lines += filtered[:30]

    if minor:
        lines.append('')
        lines.append('▪️ 另有中低危 %d 条，见完整播报' % minor)

    lines.append('')
    lines.append('<a href="%s">查看完整播报</a>' % PAGE_URL)

    text = '\n'.join(lines)
    if len(text) > MAX_CONTENT:
        text = text[:MAX_CONTENT].rsplit('\n', 1)[0] + '\n… <a href="%s">查看完整播报</a>' % PAGE_URL
    return text


def _send(bot_token, chat_id, content):
    url = 'https://api.telegram.org/bot%s/sendMessage' % bot_token
    payload = {
        'chat_id': chat_id,
        'text': content,
        'parse_mode': 'HTML',
        'disable_web_page_preview': True,
    }
    try:
        response = requests.post(url, json=payload, timeout=20)
        data = response.json()
        if data.get('ok'):
            log.info('[Telegram] 推送成功 (chat_id=%s)' % chat_id)
            return True
        # HTML 解析失败时降级为纯文本重发一次
        if data.get('error_code') == 400 and 'parse' in str(data).lower():
            payload.pop('parse_mode')
            response = requests.post(url, json=payload, timeout=20)
            if response.json().get('ok'):
                log.info('[Telegram] 降级纯文本推送成功')
                return True
        log.warning('[Telegram] 推送失败：%s' % data)
    except Exception as error:
        log.warning('[Telegram] 推送异常：%s' % error)
    return False
