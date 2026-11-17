#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# Telegram 频道推送：威胁情报完整播报（漏洞库模式 v3）
#
#   1. AI 研判：直接从 https://threat.aabyss.cn/ 抓最新研判全文
#   2. 漏洞条目：推送描述全文（info 字段，数据库/爬虫已带）
#   3. 全量推送不折叠，按危害等级排序
#   4. 超 4096 自动分片，429 限流自动重试
#   5. HTML 转义防注入，解析失败降级纯文本
# -----------------------------------------------

import json
import os
import re
import time
import requests
from datetime import datetime

import src.config as config
from src.bean.cve_info import CST, LEVEL_CN
from src.logger import log

PAGE_URL = 'https://threat.aabyss.cn/'
MSG_LIMIT = 4096
SAFE_LIMIT = 3800
SLEEP_BETWEEN = 0.6
AI_FETCH_TIMEOUT = 20

BADGE = {
    'KEV': '🚨',
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '⚪',
    '': '▫️',
}
LEVEL_RANK = {'KEV': 0, 'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, '': 5}


def to_telegram(cves):
    if not cves:
        return False

    bot_token = (config.settings.get('notify', 'telegram_bot_token', '') or '').strip()
    chat_id = (config.settings.get('notify', 'telegram_chat_id', '') or '').strip()

    if not (bot_token and chat_id):
        log.debug('[Telegram] 未配置推送渠道，跳过')
        return False

    sent_any = False

    # ---- 消息 1：AI 研判（从看板爬全文） ----
    ai = _fetch_ai_from_page()
    if ai:
        ai_msg = '<b>🤖 AI 研判 | 近期高风险漏洞</b>\n<blockquote>%s</blockquote>' % _esc(ai)
        sent_any = _send(bot_token, chat_id, ai_msg) or sent_any

    # ---- 消息 2..N：完整播报分片（含漏洞全文描述） ----
    chunks = build_chunks(cves)
    for idx, chunk in enumerate(chunks):
        ok = _send(bot_token, chat_id, chunk, seq=(idx + 1, len(chunks)))
        sent_any = sent_any or ok
        if ok and len(chunks) > 1 and idx < len(chunks) - 1:
            time.sleep(SLEEP_BETWEEN)
    return sent_any


def _total(cves):
    return sum(len(items) for items in cves.values())


# ---------------- AI 研判：从 threat.aabyss.cn 抓取 ----------------

_AI_SUMMARY_RE = re.compile(
    r'<p class="ai-summary-text">(.*?)</p>', re.DOTALL)


def _fetch_ai_from_page():
    """从 threat.aabyss.cn 首页抓取 ai-summary-text 段落全文。"""
    try:
        resp = requests.get(PAGE_URL, timeout=AI_FETCH_TIMEOUT, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; ThreatBroadcast/1.0)',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        })
        if resp.status_code != 200:
            log.warning('[Telegram] 看板页面返回 HTTP %s，AI 研判跳过' % resp.status_code)
            return ''
        match = _AI_SUMMARY_RE.search(resp.text)
        if not match:
            log.info('[Telegram] 看板上没有 AI 研判段落，跳过')
            return ''
        # 去掉 HTML 标签与实体，拿到纯文本
        raw = match.group(1)
        text = re.sub(r'<br\s*/?>', '\n', raw)
        text = re.sub(r'<[^>]+>', '', text)
        import html as _html
        text = _html.unescape(text)
        text = re.sub(r'\n{3,}', '\n\n', text).strip()
        log.info('[Telegram] 已从看板抓取 AI 研判 %d 字' % len(text))
        return text
    except requests.RequestException as error:
        log.warning('[Telegram] 抓取看板 AI 研判失败：%s' % error)
        return ''


# ---------------- 漏洞条目渲染 ----------------

def _esc(text):
    return (text or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _fallback_url(cve):
    url = (getattr(cve, 'url', '') or '').strip()
    if url:
        return url
    cid = (getattr(cve, 'id', '') or '').upper()
    if cid.startswith('CVE-'):
        return ('https://nvd.nist.gov/vuln/search/results?form_type=Basic'
                '&results_type=overview&query=%s&search_type=all' % cid)
    return ''


def _render_entry(src_name, cve):
    level = (getattr(cve, 'level', '') or '').upper()
    badge = BADGE.get(level, '▫️')
    level_cn = LEVEL_CN.get(level, '未知')

    title = _esc((getattr(cve, 'title', '') or '').strip()[:200])
    cid = _esc(getattr(cve, 'id', '') or '详情')
    time_str = _esc((getattr(cve, 'time', '') or '')[:16])
    url = _fallback_url(cve)

    # 描述全文（info 字段），去 HTML 标签已由 normalize 保证
    info_raw = (getattr(cve, 'info', '') or '').strip()
    info = _esc(info_raw[:500]) if info_raw and info_raw != (getattr(cve, 'title', '') or '') else ''

    lines = []
    head = '%s <b>[%s]</b> %s' % (badge, level_cn, title)
    if url:
        head = '<a href="%s">%s</a> %s' % (url, cid, head)
    else:
        head = '%s %s' % (cid, head)
    lines.append(head)
    lines.append('　%s · %s' % (cid if not url else _esc(src_name), time_str))
    if info:
        lines.append('<i>%s</i>' % info)
    return '\n'.join(lines)


def build_chunks(cves):
    total = _total(cves)
    now = datetime.now(CST).strftime('%Y-%m-%d %H:%M')

    header = [
        '<b>🛡 Threat Broadcast | 漏洞库播报</b>',
        '新增 <b>%d</b> 条 · %s' % (total, now),
    ]

    flat = []
    for src, items in cves.items():
        for cve in items:
            flat.append((src.NAME_CH(), cve))
    flat.sort(key=lambda pair: LEVEL_RANK.get((pair[1].level or '').upper(), 5))

    body_lines = []
    last_src = None
    for src_name, cve in flat:
        if src_name != last_src:
            body_lines.append('')
            body_lines.append('<b>━━ %s ━━</b>' % _esc(src_name))
            last_src = src_name
        body_lines.append(_render_entry(src_name, cve))

    # ---- 分片组装 ----
    chunks = []
    current = header[0] + '\n' + header[1]
    for line in body_lines:
        candidate = current + '\n' + line
        if len(candidate) > SAFE_LIMIT and len(current.strip()) > 0:
            current += '\n<i>接下页…</i>'
            chunks.append(current)
            current = line
        else:
            current = candidate
    current += '\n\n<a href="%s">🌐 完整网页版</a>' % PAGE_URL
    chunks.append(current)

    if len(chunks) > 1:
        numbered = []
        for i, chunk in enumerate(chunks):
            tag = '<b>【%d/%d】</b>\n' % (i + 1, len(chunks))
            if i == 0:
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
        if data.get('error_code') == 400 and 'parse' in str(data).lower():
            payload.pop('parse_mode')
            response = requests.post(url, json=payload, timeout=20)
            if response.json().get('ok'):
                log.info('[Telegram] 降级纯文本推送成功')
                return True
        retry = (data.get('parameters') or {}).get('retry_after')
        if data.get('error_code') == 429 and retry:
            time.sleep(min(int(retry), 30) + 1)
            response = requests.post(url, json=payload, timeout=20)
            if response.json().get('ok'):
                log.info('[Telegram] 限流后重试成功')
                return True
        log.warning('[Telegram] 推送失败：%s' % data)
    except Exception as error:
        log.warning('[Telegram] 推送异常：%s' % error)
    return False
