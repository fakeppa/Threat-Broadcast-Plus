#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# -----------------------------------------------
# 威胁情报播报入口
# -----------------------------------------------

import argparse
import os
import sys
import time

import src.config as config
from src.dao import _db
from src.logger import log

from src.crawler.avd import AliyunAVD
from src.crawler.tophant import Tophant
from src.crawler.threatbook import ThreatBook
from src.crawler.chaitin import Chaitin
from src.crawler.cert360 import Cert360
from src.crawler.nvd import NVD
from src.crawler.tenable import Tenable
from src.crawler.cisa_kev import CisaKev

import src.notice.page as page
import src.notice.mail as mail
import src.notice.wechat as wechat
import src.notice.telegram as telegram
import src.notice.kimi as kimi
import src.utils._git as git

# 防止仓库被随意 Fork 后直接运行、导致目标站点被大量请求
DEFAULT_CRAWL_PWD = os.environ.get('CRAWL_PWD') or 'AabyssTeam-Plus-F5m5bAxpaHE2CwS'


def args():
    parser = argparse.ArgumentParser(
        prog='',
        usage='威胁情报播报 - 帮助信息',
        description='从多个公开的威胁情报来源爬取并整合最新信息',
        epilog='\r\n'.join([
            '使用示例: ',
            '  python main.py -g {CRAWL_PWD} -t 60',
        ])
    )
    parser.add_argument('-g', '--git', dest='git', type=str, default=DEFAULT_CRAWL_PWD,
                        help='Github Action 的启动密码（避免被 Fork 时别人可以直接运行）')
    parser.add_argument('-t', '--top', dest='top', type=int, default=0,
                        help='播报时每个来源最多取最新的前 N 个 CVE（默认取配置文件）')
    parser.add_argument('-ac', '--auto_commit', dest='auto_commit', action='store_true', default=False,
                        help='自动提交变更到仓库（使用 Github Actions 时默认关闭）')
    parser.add_argument('-k', '--gtk', dest='gtk', type=str, default='',
                        help='Github Token，用于从 Issue 收集订阅邮箱')
    parser.add_argument('-ms', '--mail_smtp', dest='mail_smtp', type=str, default='',
                        help='发送播报邮件的 SMTP 服务器')
    parser.add_argument('-mu', '--mail_user', dest='mail_user', type=str, default='',
                        help='发送播报邮件的邮箱账号')
    parser.add_argument('-mp', '--mail_pass', dest='mail_pass', type=str, default='',
                        help='发送播报邮件的邮箱密码 / 授权码')
    parser.add_argument('-qu', '--qq_user', dest='qq_user', type=str, default='',
                        help='（预留）向 QQ 群发送播报信息的账号')
    parser.add_argument('-qp', '--qq_pass', dest='qq_pass', type=str, default='',
                        help='（预留）向 QQ 群发送播报信息的密码')
    parser.add_argument('--no-mail', dest='no_mail', action='store_true', default=False,
                        help='跳过邮件推送')
    parser.add_argument('--no-wechat', dest='no_wechat', action='store_true', default=False,
                        help='跳过微信推送')
    return parser.parse_args()


def get_options(argv):
    if argv.git != DEFAULT_CRAWL_PWD:
        # Github Action 会传入 secrets.CRAWL_PWD；仓库被 Fork 且未配置 secret 时为空值
        log.warning('启动密码不匹配，爬虫进程终止（这是防止 Fork 滥用的保护措施）')
        sys.exit(0)

    return {
        'top': argv.top or int(config.settings.get('crawler', 'top', 60) or 60),
        'auto_commit': bool(argv.auto_commit or config.settings.get('github', 'auto_commit', False)),
        'gtk': argv.gtk or config.settings.get('github', 'gtk', ''),
        'mail_smtp': argv.mail_smtp or config.settings.get('notify', 'mail_smtp', 'smtp.qq.com'),
        'mail_port': int(config.settings.get('notify', 'mail_port', 465) or 465),
        'mail_user': argv.mail_user or config.settings.get('notify', 'mail_user', ''),
        'mail_pass': argv.mail_pass or config.settings.get('notify', 'mail_pass', ''),
        'no_mail': argv.no_mail,
        'no_wechat': argv.no_wechat,
    }


def build_sources():
    """按展示顺序构建启用的情报源。

    已停用的来源（保留代码但不参与抓取）：
      - Cert360：站点证书过期且内容停留在 2024 年，暂不启用
      - QiAnXin / RedQueen / Nsfocus：站点改版或接口失效
      - CNVD / CNNVD / AnQuanKe：反爬或停止 CVE 分析
      - Vas：旧版斗象接口，已由 Tophant 替代
    """
    return [
        AliyunAVD(),
        Tophant(),
        ThreatBook(),
        Chaitin(),
        # Cert360(),       # 证书过期 + 已停止更新，确认恢复后再启用
        NVD(),
        Tenable(),
        CisaKev(),
    ]


def run(options):
    started = time.time()
    top = options['top']
    sources = build_sources()

    conn = _db.connect()
    all_cves = {}
    active = set()

    try:
        _db.init(conn)
        log.info('=' * 60)
        log.info('威胁情报播报启动 | 每源上限 %d 条 | 数据库 %s（%.1f MB）'
                 % (top, _db.db_path(), _db.size() / 1024.0 / 1024.0))

        for src in sources:
            try:
                cves = src.cves(conn, top)
            except Exception as error:
                log.error('来源 [%s] 抓取异常：%s' % (src.NAME_CH(), error))
                cves = []

            if cves:
                all_cves[src] = cves
                active.add(src.NAME_CH())

        total = sum(len(items) for items in all_cves.values())
        log.info('=' * 60)
        log.info('本次共获取 %d 个来源 / %d 条新增情报' % (len(all_cves), total))
        for src, items in all_cves.items():
            log.info('  - %-28s %3d 条' % (src.NAME_CH(), len(items)))

        # 先清理过期 / 超量归档，保证页面与提交的数据库都是裁剪后的结果
        _db.prune(conn)

        # 有新情报或还没有 AI 研判时，调用 Kimi 生成近 N 天风险摘要
        summary_changed = False
        try:
            if all_cves or not kimi.has_summary():
                summary_changed = kimi.to_summary(conn)
        except Exception as error:
            log.error('[AI] 生成风险研判异常，跳过：%s' % error)

        # 有新情报、新摘要，或页面从未生成过时，才重建页面，避免产生无意义的提交
        if all_cves or summary_changed or not os.path.exists(page.HTML_PATH):
            page.to_page(conn, top, sources, active)
        else:
            log.info('本次没有新增情报，播报页面保持不变')

        if all_cves:
            if options['no_mail']:
                log.info('[邮件] 已通过 --no-mail 跳过')
            else:
                mail.to_mail(
                    options['gtk'], all_cves,
                    options['mail_smtp'], options['mail_user'],
                    options['mail_pass'], options['mail_port'],
                )

            if options['no_wechat']:
                log.info('[微信/Telegram] 已通过 --no-wechat 跳过')
            else:
                wechat.to_wechat(all_cves)
                telegram.to_telegram(all_cves)

            if options['auto_commit']:
                git.auto_commit()

        log.info('=' * 60)
        log.info('全部完成，总耗时 %.1f 秒，数据库 %.1f MB'
                 % (time.time() - started, _db.size() / 1024.0 / 1024.0))
        return 0
    finally:
        _db.close(conn)


def main():
    options = get_options(args())
    try:
        return run(options)
    except KeyboardInterrupt:
        log.warning('用户中断')
        return 130
    except Exception as error:
        log.exception('程序运行失败：%s' % error)
        return 1


if __name__ == '__main__':
    sys.exit(main())
