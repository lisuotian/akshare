import akshare as ak, inspect, json, time, traceback, socket, re, sys
from pathlib import Path
from datetime import datetime

cases = {
 'calendar': lambda: ak.tool_trade_date_hist_sina(),
 'a_stock_spot': lambda: ak.stock_zh_a_spot_em(),
 'a_stock_hist': lambda: ak.stock_zh_a_hist(symbol='600519', period='daily', start_date='20260101', end_date='20261001', adjust=''),
 'a_stock_minute': lambda: ak.stock_zh_a_minute(symbol='sh600519', period='1', adjust=''),
 'stock_info': lambda: ak.stock_individual_info_em(symbol='600519'),
 'index_spot': lambda: ak.stock_zh_index_spot(),
 'index_hist': lambda: ak.stock_zh_index_daily_em(symbol='sh000001'),
 'fund_names': lambda: ak.fund_name_em(),
 'fund_hist': lambda: ak.fund_etf_hist_sina(symbol='sh510300'),
 'bond_convertible_spot': lambda: ak.bond_zh_hs_cov_spot(),
 'futures_realtime': lambda: ak.futures_zh_realtime(symbol='白糖'),
 'futures_hist': lambda: ak.futures_main_sina(symbol='RB0'),
 'option_spot': lambda: ak.option_current_em(),
 'currency_hist': lambda: ak.currency_hist(symbol='usd-cny', period='每日', start_date='20260101', end_date='20261001'),
 'news_cctv': lambda: ak.news_cctv(date='20260930'),
 'macro_gdp': lambda: ak.macro_china_gdp(),
 'crypto_spot': lambda: ak.crypto_js_spot(),
 'air_quality': lambda: ak.air_quality_rank(),
}
url_re=re.compile(r'https?://[^\s\"\'<>]+')
def urls_from_text(t): return sorted(set(u.rstrip('.,);]') for u in url_re.findall(t or '')))
def domains(urls):
 out=[]
 for u in urls:
  host=re.sub(r'^https?://','',u).split('/',1)[0].split(':',1)[0]
  try: ips=sorted(set(socket.gethostbyname_ex(host)[2]))
  except Exception as e: ips=[f'DNS_ERROR:{type(e).__name__}:{e}']
  out.append({'host':host,'ips':ips})
 return out
path=Path('.audit/representative_results.jsonl'); path.write_text('',encoding='utf-8')
for name,fn in cases.items():
 t=time.time(); result={'name':name,'started_at':datetime.now().astimezone().isoformat()}
 try:
  x=fn(); result.update(status='ok' if not (hasattr(x,'empty') and x.empty) else 'empty', elapsed_sec=round(time.time()-t,3), shape=list(x.shape) if hasattr(x,'shape') and x.shape is not None else None, columns=[str(c) for c in list(getattr(x,'columns',[]))[:20]])
 except Exception as e:
  tb=traceback.format_exc(limit=12); urls=urls_from_text(str(e)+'\n'+tb)
  if not urls:
   try: urls=urls_from_text(inspect.getsource(fn))
   except Exception: pass
  result.update(status='error',elapsed_sec=round(time.time()-t,3),error=f'{type(e).__name__}: {e}',traceback=tb[-7000:],urls=urls,domains=domains(urls))
 with path.open('a',encoding='utf-8') as f: f.write(json.dumps(result,ensure_ascii=False)+'\n')
 print(json.dumps(result,ensure_ascii=False),flush=True)
