#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# Telegram 频道推送：威胁情报播报
# 由 main.py 在每次抓取后调用 to_telegram(all_cves)
#
# 配置来源（settings.yml 已挂 ENV）：
#   TELEGRAM_BOT_TOKEN : BotFather 给的 API Token
#   TELEGRAM_CHAT_ID   : @ThR3at_Int3l 或数字 -1003972934676
# -----------------------------------------------

import requests
from datetime import datetime

import src.config as config
from src.bean.cve_info import CST
from src.logger import log

PAGE_URL = 'https://threat.aabyss.cn/'
MAX_CONTENT = 4000  # sendMessage 上限 4096，留余量


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


def build_html(cves):
    lines = [
        '<b> Threat Broadcast</b>',
        '新增 <b>%d</b> 条 · %s' % (_total(cves), datetime.now(CST).strftime('%Y-%m-%d %H:%M')),
        '',
    ]

    for src, items in cves.items():
        lines.append('<b>%s</b>（%d 条）' % (src.NAME_CH(), len(items)))
        for cve in items[:5]:
            title = (cve.title or '').strip()
            title = (title.replace('&', '&amp;').replace('<', '&lt;')
                          .replace('>', '&gt;'))
            if len(title) > 80:
                title = title[:80] + '…'
            identifier = cve.id or '详情'
            if cve.url:
                lines.append('- <a href="%s">%s</a> %s' % (cve.url, identifier, title))
            else:
                lines.append('- %s %s' % (identifier, title))
        if len(items) > 5:
            lines.append('- 其余 %d 条查看完整播报' % (len(items) - 5))
        lines.append('')

    lines.append('<a href="%s">查看完整播报</a>' % PAGE_URL)
    text = '\n'.join(lines)
    return text[:MAX_CONTENT]


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
        log.warning('[Telegram] 推送失败：%s' % data)
    except Exception as error:
        log.warning('[Telegram] 推送异常：%s' % error)
    return False
