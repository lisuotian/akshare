import concurrent.futures, json, pathlib, re, time, ipaddress
from urllib.parse import urlparse
import requests

all_hosts=json.loads(pathlib.Path('.audit/all_source_host_connectivity.json').read_text(encoding='utf-8'))['results']
issue_roots={x['root_domain'] for x in json.loads(pathlib.Path('.audit/all_source_root_domain_issues_detail.json').read_text(encoding='utf-8'))}
# Build literal source URLs by host from the original inventory, skipping templates and long malformed fragments.
source={}
for line in pathlib.Path('.audit/akshare_urls_dns.jsonl').read_bytes().decode('utf-8','replace').splitlines():
 try: row=json.loads(line)
 except: continue
 url=str(row.get('url') or '')
 host=str(row.get('host') or '').lower().rstrip('.')
 if not url or not host or '{' in url or '}' in url or '\\' in url: continue
 if url.startswith(('http://','https://')):
  source.setdefault(host,set()).add(url)

def check(host):
 root=next((x['root_domain'] for x in all_hosts if x['host']==host),None)
 if root not in issue_roots: return None
 urls=sorted(source.get(host,set()))[:3]
 out={'host':host,'root_domain':root,'urls':urls,'probes':[]}
 for url in urls:
  try:
   parsed=urlparse(url)
   if parsed.scheme not in ('http','https'): continue
   t=time.time()
   try:
    r=requests.get(url,headers={'User-Agent':'Mozilla/5.0','Accept':'*/*','Connection':'close'},timeout=(4,8),allow_redirects=False)
    out['probes'].append({'url':url,'status':r.status_code,'elapsed_sec':round(time.time()-t,3),'bytes':len(r.content),'location':r.headers.get('location','')[:300]})
   except Exception as e:
    out['probes'].append({'url':url,'error':f'{type(e).__name__}: {e}','elapsed_sec':round(time.time()-t,3)})
  except Exception as e: out['probes'].append({'url':url,'error':f'{type(e).__name__}: {e}'})
 return out
hosts=[x['host'] for x in all_hosts if x['root_domain'] in issue_roots]
results=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
 for i,f in enumerate(concurrent.futures.as_completed([pool.submit(check,h) for h in hosts]),1):
  x=f.result()
  if x: results.append(x)
  print(f'[{i}/{len(hosts)}] {x["host"] if x else "skip"}',flush=True)
results.sort(key=lambda x:x['host'])
pathlib.Path('.audit/issue_root_actual_url_probes.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
print('hosts=',len(results),'probes=',sum(len(x['probes']) for x in results))
