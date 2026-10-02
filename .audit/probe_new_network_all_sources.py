import concurrent.futures, json, pathlib, re, socket, time, ipaddress
from urllib.parse import urlparse
import requests

src=pathlib.Path('.audit/akshare_urls_dns.jsonl')
out_prefix='.audit/akshare_new_network'

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
    host=str(row.get('host') or '').strip().lower().rstrip('.')
    root=root_domain(host)
    if not root: continue
    url=str(row.get('url') or '')
    rec=hosts.setdefault(host,{'host':host,'root_domain':root,'urls':set()})
    if url.startswith(('http://','https://')) and '{' not in url and '}' not in url and '\\' not in url:
        rec['urls'].add(url)

def choose_urls(urls):
    # Prefer concrete source paths over bare host roots; cap at two to keep the scan controlled.
    vals=sorted(urls, key=lambda u: (urlparse(u).path in ('','/'), -len(u), u))
    return vals[:2]

def probe_one(rec):
    host=rec['host']; result={'host':host,'root_domain':rec['root_domain'],'dns_ips':[],'dns_error':'','source_urls':choose_urls(rec['urls']),'probes':[]}
    try: result['dns_ips']=sorted(set(socket.gethostbyname_ex(host)[2]))
    except Exception as e: result['dns_error']=f'{type(e).__name__}: {e}'
    urls=[f'https://{host}/',f'http://{host}/']+result['source_urls']
    seen=set()
    for url in urls:
        if url in seen: continue
        seen.add(url)
        t=time.time()
        try:
            r=requests.get(url,headers={'User-Agent':'Mozilla/5.0','Accept':'*/*','Connection':'close'},timeout=(4,8),allow_redirects=False,verify=True)
            result['probes'].append({'url':url,'status':r.status_code,'elapsed_sec':round(time.time()-t,3),'bytes':len(r.content),'location':r.headers.get('location','')[:300]})
        except Exception as e:
            result['probes'].append({'url':url,'error':f'{type(e).__name__}: {e}','elapsed_sec':round(time.time()-t,3)})
    return result

items=list(hosts.values()); results=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    fs=[pool.submit(probe_one,x) for x in items]
    for i,f in enumerate(concurrent.futures.as_completed(fs),1):
        results.append(f.result())
        if i%25==0 or i==len(fs): print(f'progress {i}/{len(fs)}',flush=True)
results.sort(key=lambda x:x['host'])
meta={'generated_at':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'host_count':len(results),'root_domain_count':len(set(x['root_domain'] for x in results))}
pathlib.Path(out_prefix+'_host_probes.json').write_text(json.dumps({'meta':meta,'results':results},ensure_ascii=False,indent=2),encoding='utf-8')

def bad(p):
    if p.get('error'): return True
    s=int(p.get('status',0)); return s in {401,403,407,408,429} or s>=500

def is_transport(p): return bool(p.get('error'))
agg={}
for rec in results:
    bads=[p for p in rec['probes'] if bad(p)]
    if not bads and not rec['dns_error']: continue
    item=agg.setdefault(rec['root_domain'],{'root_domain':rec['root_domain'],'ips':set(),'hosts':set(),'evidence':[]})
    item['ips'].update(rec['dns_ips']); item['hosts'].add(rec['host'])
    for p in bads:
        item['evidence'].append({'host':rec['host'],'url':p.get('url',''),'ips':rec['dns_ips'],'status':p.get('status'),'error':p.get('error','')})
    if rec['dns_error']:
        item['evidence'].append({'host':rec['host'],'url':'','ips':rec['dns_ips'],'status':None,'error':rec['dns_error']})
all_issues=[{'root_domain':k,'ips':sorted(v['ips'])} for k,v in sorted(agg.items())]
transport=[]
for k,v in sorted(agg.items()):
    if any(e.get('error') for e in v['evidence']): transport.append({'root_domain':k,'ips':sorted(v['ips'])})
detail=[{'root_domain':k,'ips':sorted(v['ips']),'hosts':sorted(v['hosts']),'evidence':v['evidence']} for k,v in sorted(agg.items())]
pathlib.Path(out_prefix+'_connection_issues.json').write_text(json.dumps(all_issues,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
pathlib.Path(out_prefix+'_transport_failures.json').write_text(json.dumps(transport,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
pathlib.Path(out_prefix+'_connection_issues_detail.json').write_text(json.dumps(detail,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('SUMMARY',json.dumps({'hosts':len(results),'roots':meta['root_domain_count'],'issue_roots':len(all_issues),'transport_roots':len(transport),'issue_ips':len(set(ip for x in all_issues for ip in x['ips']))},ensure_ascii=False))
