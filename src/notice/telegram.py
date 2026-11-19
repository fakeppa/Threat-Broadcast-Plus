#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# Telegram 频道推送：威胁情报完整播报（漏洞库模式 v4）
#
#   1. AI 研判：实时从 https://threat.aabyss.cn/ 抓全文
#   2. 单条消息合并发送（标题+AI+漏洞条目拼一块），
#      只有真超 4096 才分片；正常批次一律一条
#   3. 每条带 POC/EXP 字段：本地启发式判定（标题/描述/URL 关键词）
#   4. 按危害等级排序，HTML 转义，429 限流重试
# -----------------------------------------------

import re
import time
import requests
from datetime import datetime

import src.config as config
from src.bean.cve_info import CST, LEVEL_CN
from src.logger import log

PAGE_URL = 'https://threat.aabyss.cn/'
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

# ---- POC/EXP 启发式关键词（不区分大小写） ----
_POC_RE = re.compile(
    r'(poc|proof[- ]of[- ]concept|exploit|exp\b|\bexp\)|weaponiz|'
    r'利用代码|漏洞利用|利用程序|概念验证|在野利用|exp 已公开)',
    re.IGNORECASE)
# URL 里带这些特征也算（如 exp 库/GitHub exploit 仓库）
_POC_URL_RE = re.compile(
    r'(exploit[-_]?db|exploit\.db|github\.com/[^/]+/[Pp][Oo][Cc]|poc\.|'
    r'exploit/|/exploits/|packetstorm|seclists|vulners)',
    re.IGNORECASE)


def _has_poc(cve):
    """本地启发式：标题/描述/URL 任一命中即判有 POC。"""
    title = (getattr(cve, 'title', '') or '')
    info = (getattr(cve, 'info', '') or '')
    url = (getattr(cve, 'url', '') or '')
    if _POC_URL_RE.search(url):
        return True
    text = title + ' ' + info
    return bool(_POC_RE.search(text))


MAX_CHUNKS = 5             # 单次推送最多 5 片（约 30-40 条全文），防爆频道
HEADLINE_ONLY_AFTER = 25   # 超过 25 条后：重要级全文，其余只推编号+标题一行


def to_telegram(cves):
    if not cves:
        return False

    bot_token = (config.settings.get('notify', 'telegram_bot_token', '') or '').strip()
    chat_id = (config.settings.get('notify', 'telegram_chat_id', '') or '').strip()

    if not (bot_token and chat_id):
        log.debug('[Telegram] 未配置推送渠道，跳过')
        return False

    total_raw = _total(cves)
    # 重启/首次运行会把全量当增量，条数超过阈值时降级为「重要全文 + 其余摘要」
    compact = total_raw > HEADLINE_ONLY_AFTER
    if compact:
        log.info('[Telegram] 本次新增 %d 条超过 %d，启用紧凑模式' % (total_raw, HEADLINE_ONLY_AFTER))

    chunks = build_chunks(cves, compact=compact)
    # 硬上限：再多也只发前 MAX_CHUNKS 片，尾部提示看网页版
    if len(chunks) > MAX_CHUNKS:
        log.warning('[Telegram] 分片 %d 超上限 %d，截断' % (len(chunks), MAX_CHUNKS))
        chunks = chunks[:MAX_CHUNKS]
        chunks[-1] = chunks[-1].replace('🌐 网页版', '⚠️ 条目过多已截断，全部内容见 🌐 网页版')

    sent_any = False
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


def _render_entry(cve, src_label='', compact=False):
    level = (getattr(cve, 'level', '') or '').upper()
    badge = BADGE.get(level, '▫️')
    level_cn = LEVEL_CN.get(level, '未知')
    poc = _has_poc(cve)
    poc_mark = ' <b>💣[POC]</b>' if poc else ''

    title = _esc((getattr(cve, 'title', '') or '').strip()[:160])
    cid = _esc(getattr(cve, 'id', '') or '详情')
    time_str = _esc((getattr(cve, 'time', '') or '')[:10])
    url = _fallback_url(cve)

    # 紧凑模式：低优先级条目只推一行（编号+等级+标题）
    important = level in ('KEV', 'CRITICAL', 'HIGH') or poc
    if compact and not important:
        if url:
            return '<a href="%s">%s</a> %s [%s] %s' % (url, cid, badge, level_cn, title)
        return '%s %s [%s] %s' % (cid, badge, level_cn, title)

    # 描述全文：normalize 上限 1200 字，这里只截到 900 控制单条体积
    info_raw = (getattr(cve, 'info', '') or '').strip()
    if info_raw == (getattr(cve, 'title', '') or ''):
        info_raw = ''
    info = _esc(info_raw[:900]) if info_raw else ''

    if url:
        head = '<a href="%s">%s</a> %s%s <b>[%s]</b>' % (url, cid, badge, poc_mark, level_cn)
    else:
        head = '%s %s%s <b>[%s]</b>' % (cid, badge, poc_mark, level_cn)
    line = head + ' ' + title + '\n　' + time_str
    if info:
        line += '\n　<i>%s</i>' % info
    return line


def _merge_entries(cves):
    """跨源合并同一 CVE：保留等级最高的一条记录，描述取所有源里最长的。

    斗象/微步等中文源常只有一句话，NVD/CISA 有完整技术描述；
    合并后标题用等级最高记录的，描述用最长的，来源标注列出全部。
    """
    merged = {}
    for src, items in cves.items():
        for cve in items:
            cid = (getattr(cve, 'id', '') or '').upper()
            key = cid if cid.startswith('CVE-') else '%s|%s' % (
                src.NAME_CH(), getattr(cve, 'title', ''))
            level = (getattr(cve, 'level', '') or '').upper()
            rank = LEVEL_RANK.get(level, 5)

            if key not in merged:
                merged[key] = {
                    'cve': cve, 'rank': rank, 'level': level,
                    'sources': [src.NAME_CH()],
                }
            else:
                entry = merged[key]
                if src.NAME_CH() not in entry['sources']:
                    entry['sources'].append(src.NAME_CH())
                # 等级更高的记录优先作为主条目（KEV 标记不能丢）
                if rank < entry['rank']:
                    old_info = getattr(entry['cve'], 'info', '') or ''
                    new_info = (getattr(cve, 'info', '') or '')
                    entry['cve'] = cve
                    entry['rank'] = rank
                    entry['level'] = level
                    # 主条目换了但描述短的，保留原来的长描述
                    if len(new_info) < len(old_info):
                        setattr(entry['cve'], 'info', old_info)
                else:
                    # 主条目不变，描述取更长的
                    old_info = (getattr(entry['cve'], 'info', '') or '')
                    new_info = (getattr(cve, 'info', '') or '')
                    if len(new_info) > len(old_info):
                        setattr(entry['cve'], 'info', new_info)
    return merged


def build_chunks(cves, compact=False):
    now = datetime.now(CST).strftime('%Y-%m-%d %H:%M')

    ai = _fetch_ai_from_page()

    merged = _merge_entries(cves)
    # 按等级排序，同级按编号倒序（新的在前）
    flat = sorted(merged.items(), key=lambda kv: (
        kv[1]['rank'], getattr(kv[1]['cve'], 'time', ''), kv[0]))

    body_lines = []
    last_sources = None
    for key, entry in flat:
        cve = entry['cve']
        src_label = ' / '.join(entry['sources'])
        if src_label != last_sources:
            body_lines.append('<b>—— %s ——</b>' % _esc(src_label))
            last_sources = src_label
        body_lines.append(_render_entry(cve, src_label, compact=compact))

    total = len(merged)

    # ---- 单块组装（正常批次一条搞定） ----
    header = '<b>🛡 Threat Broadcast · %s</b>\n新增 <b>%d</b> 条' % (now, total)
    if compact:
        header += '（重要漏洞全文，其余仅标题）'
    if ai:
        header += '\n🤖 <b>AI 研判：</b>' + _esc(ai)

    current = header
    for line in body_lines:
        candidate = current + '\n' + line
        if len(candidate) > SAFE_LIMIT:
            current += '\n<i>…接下页</i>'
            chunks_done = current
            # 用 list 暂存，见下
            if not hasattr(build_chunks, '_acc'):
                build_chunks._acc = []
            build_chunks._acc.append(chunks_done)
            current = line
        else:
            current = candidate
    current += '\n<a href="%s">🌐 网页版</a>' % PAGE_URL

    if hasattr(build_chunks, '_acc') and build_chunks._acc:
        build_chunks._acc.append(current)
        chunks = build_chunks._acc
        del build_chunks._acc
    else:
        chunks = [current]

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
