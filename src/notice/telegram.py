#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# Telegram 频道推送：威胁情报完整播报（漏洞库模式）
#
# 频道定位 = 漏洞库 + 危害告警，不是导读：
#   1. 所有新增条目全量推送（不分重要次要）
#   2. 按危害等级排序：KEV > 严重 > 高危 > 中危 > 低危 > 未知
#   3. 每条带等级徽章 + 可点链接 + 披露时间 + 来源
#   4. 超过单条 4096 上限自动分片多条连续发送
#   5. 顶部附 Kimi AI 研判摘要（有则推）
#   6. HTML 转义防注入，解析失败自动降级纯文本
# -----------------------------------------------

import json
import os
import requests
from datetime import datetime

import src.config as config
from src.bean.cve_info import CST, LEVEL_CN
from src.logger import log

PAGE_URL = 'https://threat.aabyss.cn/'
MSG_LIMIT = 4096          # Telegram 单条上限
SAFE_LIMIT = 3800         # 留余量给分片头尾
SLEEP_BETWEEN = 0.6       # 分片间隔秒，防 429 限流

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

    sent_any = False

    # ---- 消息 1：AI 研判全文（独立一条，不截断） ----
    ai = _load_ai_summary()
    if ai:
        ai_msg = '<b>🤖 AI 研判 | 近期高风险漏洞</b>\n<blockquote>%s</blockquote>' % _esc(ai)
        sent_any = _send(bot_token, chat_id, ai_msg) or sent_any

    # ---- 消息 2..N：完整播报分片 ----
    chunks = build_chunks(cves, with_ai=False)
    for idx, chunk in enumerate(chunks):
        ok = _send(bot_token, chat_id, chunk, seq=(idx + 1, len(chunks)))
        sent_any = sent_any or ok
        if ok and len(chunks) > 1 and idx < len(chunks) - 1:
            import time
            time.sleep(SLEEP_BETWEEN)
    return sent_any


def _total(cves):
    return sum(len(items) for items in cves.values())


def _load_ai_summary():
    try:
        with open(SUMMARY_PATH, 'r', encoding=config.CHARSET) as f:
            data = json.load(f)
        content = str(data.get('content') or '').strip()
        return content if content else ''
    except (OSError, ValueError):
        return ''


def _esc(text):
    return (text or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _fallback_url(cve):
    """来源没给链接时按 CVE 编号生成 NVD 查询链接，保证永远可点。"""
    url = (cve.url or '').strip()
    if url:
        return url
    cid = (cve.id or '').upper()
    if cid.startswith('CVE-'):
        return ('https://nvd.nist.gov/vuln/search/results?form_type=Basic'
                '&results_type=overview&query=%s&search_type=all' % cid)
    return ''


def build_chunks(cves, with_ai=True):
    """渲染完整播报并按消息上限切成若干片。with_ai=False 时不内嵌研判（独立发送时用）。"""
    total = _total(cves)
    now = datetime.now(CST).strftime('%Y-%m-%d %H:%M')

    header = [
        '<b>🛡 Threat Broadcast | 漏洞库播报</b>',
        '新增 <b>%d</b> 条 · %s' % (total, now),
    ]

    ai_block = ''
    if with_ai:
        ai = _load_ai_summary()
        if ai:
            ai_block = '\n<blockquote>%s</blockquote>' % _esc(ai)

    # ---- 全量条目按等级排序 ----
    flat = []
    for src, items in cves.items():
        for cve in items:
            flat.append((src.NAME_CH(), cve))
    flat.sort(key=lambda pair: LEVEL_RANK.get((pair[1].level or '').upper(), 5))

    body_lines = []
    last_src = None
    for src_name, cve in flat:
        level = (cve.level or '').upper()
        badge = BADGE.get(level, '▫️')
        level_cn = LEVEL_CN.get(level, '未知')

        title = _esc((cve.title or '').strip()[:90])
        cid = _esc(cve.id or '详情')
        time_str = _esc((cve.time or '')[:16])
        url = _fallback_url(cve)

        # 来源变更时插入来源标题
        if src_name != last_src:
            body_lines.append('')
            body_lines.append('<b>━━ %s ━━</b>' % _esc(src_name))
            last_src = src_name

        line = '%s <b>[%s]</b> %s' % (badge, level_cn, title)
        detail = '%s · %s' % (cid, time_str)
        if url:
            line += '\n　　<a href="%s">%s%s</a>' % (url, cid, detail)
        else:
            line += '\n　　%s%s' % (cid, detail)
        body_lines.append(line)

    # ---- 组装分片 ----
    chunks = []
    current = header[0] + '\n' + header[1] + (ai_block if ai_block else '')
    first_chunk = True
    for line in body_lines:
        candidate = current + '\n' + line
        if len(candidate) > SAFE_LIMIT and len(current.strip()) > 0:
            # 收尾本片
            if first_chunk:
                current += '\n\n<i>接下页…</i>'
                first_chunk = False
            else:
                current += '\n<i>接下页…</i>'
            chunks.append(current)
            current = line  # 新片开头接续本行
        else:
            current = candidate
    # 最后一片收尾
    current += '\n\n<a href="%s">🌐 完整网页版</a>' % PAGE_URL
    chunks.append(current)

    # 给每片加序号头（多片时）
    if len(chunks) > 1:
        numbered = []
        for i, chunk in enumerate(chunks):
            tag = '<b>【%d/%d】</b>\n' % (i + 1, len(chunks))
            if i == 0:
                # 第一片已有大标题，序号插在标题后
                lines = chunk.split('\n')
                lines.insert(1, tag.strip())
                numbered.append('\n'.join(lines))
            else:
                numbered.append(tag + chunk)
        chunks = numbered

    return chunks


def _send(bot_token, chat_id, content, seq=None):
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
            if seq:
                log.info('[Telegram] 分片 %d/%d 推送成功' % seq)
            else:
                log.info('[Telegram] 推送成功 (chat_id=%s)' % chat_id)
            return True
        # HTML 解析失败时降级为纯文本重发一次
        if data.get('error_code') == 400 and 'parse' in str(data).lower():
            payload.pop('parse_mode')
            response = requests.post(url, json=payload, timeout=20)
            if response.json().get('ok'):
                log.info('[Telegram] 降级纯文本推送成功')
                return True
        # 429 限流：读取 retry_after 重试一次
        retry = (data.get('parameters') or {}).get('retry_after')
        if data.get('error_code') == 429 and retry:
            import time
            time.sleep(min(int(retry), 30) + 1)
            response = requests.post(url, json=payload, timeout=20)
            if response.json().get('ok'):
                log.info('[Telegram] 限流后重试成功')
                return True
        log.warning('[Telegram] 推送失败：%s' % data)
    except Exception as error:
        log.warning('[Telegram] 推送异常：%s' % error)
    return False
