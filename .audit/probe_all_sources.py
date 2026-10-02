import concurrent.futures, json, pathlib, re, socket, time, ipaddress
from urllib.parse import urlparse
import requests

src = pathlib.Path('.audit/akshare_urls_dns.jsonl')

def root_domain(host):
    host=(host or '').strip().lower().rstrip('.')
    if not host or any(ch in host for ch in '{}\\/ '): return None
    try: ipaddress.ip_address(host); return None
    except ValueError: pass
    labels=host.split('.')
    if len(labels)<2 or any(not re.fullmatch(r'[a-z0-9-]+', x) for x in labels): return None
    cc={'cn','uk','au','nz','jp','kr','hk','tw','sg','in','za','br','mx','tr','ru'}
    sld={'com','net','org','gov','edu','ac','co','or','ne'}
    return '.'.join(labels[-3:]) if len(labels)>=3 and labels[-1] in cc and labels[-2] in sld else '.'.join(labels[-2:])

hosts={}
for line in src.read_bytes().decode('utf-8','replace').splitlines():
    try: row=json.loads(line)
    except: continue
    host=(row.get('host') or '').strip().lower().rstrip('.')
    root=root_domain(host)
    if not root: continue
    try: ips=sorted(set(str(x) for x in row.get('ips') or [] if ipaddress.ip_address(str(x))))
    except: ips=[]
    rec=hosts.setdefault(host,{'host':host,'root_domain':root,'ips':set(),'sample_urls':set()})
    rec['ips'].update(ips)
    if row.get('url'): rec['sample_urls'].add(row['url'])
for rec in hosts.values():
    rec['ips']=sorted(rec['ips'])
    rec['sample_urls']=sorted(rec['sample_urls'])[:3]

session_headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36','Accept':'*/*','Connection':'close'}
def probe(rec):
    result={'host':rec['host'],'root_domain':rec['root_domain'],'ips':rec['ips'],'sample_urls':rec['sample_urls'],'probes':[]}
    for scheme in ('https','http'):
        url=f'{scheme}://{rec["host"]}/'
        started=time.time()
        try:
            r=requests.get(url,headers=session_headers,timeout=(4,7),allow_redirects=False,verify=True)
            result['probes'].append({'scheme':scheme,'url':url,'status':r.status_code,'elapsed_sec':round(time.time()-started,3),'bytes':len(r.content),'location':r.headers.get('location','')[:300]})
        except Exception as exc:
            result['probes'].append({'scheme':scheme,'url':url,'error':f'{type(exc).__name__}: {exc}','elapsed_sec':round(time.time()-started,3)})
    return result

items=list(hosts.values()); results=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    futures=[pool.submit(probe,item) for item in items]
    for i,f in enumerate(concurrent.futures.as_completed(futures),1):
        results.append(f.result())
        print(f'[{i}/{len(items)}] {results[-1]["host"]}',flush=True)
results.sort(key=lambda x:x['host'])
pathlib.Path('.audit/all_source_host_connectivity.json').write_text(json.dumps({'host_count':len(results),'generated_at':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'results':results},ensure_ascii=False,indent=2),encoding='utf-8')
# Root-level aggregate in the same shape as clean.json. Only transport/access failures are included.
agg={}
for rec in results:
    transport=[]; access=[]
    for p in rec['probes']:
        if 'error' in p: transport.append(p)
        elif p['status'] in {401,403,407,408,429} or p['status']>=500: access.append(p)
    if transport or access:
        a=agg.setdefault(rec['root_domain'],{'root_domain':rec['root_domain'],'ips':set(),'hosts':set(),'transport_failures':[],'access_failures':[]})
        a['ips'].update(rec['ips']); a['hosts'].add(rec['host']); a['transport_failures'].extend(transport); a['access_failures'].extend(access)
clean=[{'root_domain':k,'ips':sorted(v['ips'])} for k,v in sorted(agg.items())]
pathlib.Path('.audit/all_source_root_domain_issues.json').write_text(json.dumps(clean,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
detail=[]
for k,v in sorted(agg.items()):
    detail.append({'root_domain':k,'ips':sorted(v['ips']),'hosts':sorted(v['hosts']),'transport_failures':v['transport_failures'],'access_failures':v['access_failures']})
pathlib.Path('.audit/all_source_root_domain_issues_detail.json').write_text(json.dumps(detail,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('SUMMARY hosts=',len(results),'roots=',len(set(x['root_domain'] for x in results)),'issue_roots=',len(clean),'issue_ips=',len(set(ip for x in clean for ip in x['ips'])))
