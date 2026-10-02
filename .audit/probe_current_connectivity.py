import concurrent.futures, json, pathlib, re, socket, time, ipaddress
from urllib.parse import urlparse
import requests

payload=json.loads(pathlib.Path('.audit/akshare_new_network_host_probes.json').read_text(encoding='utf-8'))
# Use all source hosts, but aggregate status to root domain.
def probe(rec):
    out={'host':rec['host'],'root_domain':rec['root_domain'],'dns_ips':[],'dns_error':'','checks':[]}
    try: out['dns_ips']=sorted(set(socket.gethostbyname_ex(rec['host'])[2]))
    except Exception as e: out['dns_error']=f'{type(e).__name__}: {e}'
    urls=[]
    for u in rec.get('source_urls') or []:
        if u not in urls: urls.append(u)
    # Root checks are only supplemental; actual source URLs drive availability.
    for u in urls[:2]:
        t=time.time()
        try:
            r=requests.get(u,headers={'User-Agent':'Mozilla/5.0','Accept':'*/*','Connection':'close'},timeout=(4,8),allow_redirects=False,verify=True)
            out['checks'].append({'url':u,'status':r.status_code,'elapsed_sec':round(time.time()-t,3),'bytes':len(r.content)})
        except Exception as e:
            out['checks'].append({'url':u,'error':f'{type(e).__name__}: {e}','elapsed_sec':round(time.time()-t,3)})
    return out
items=payload['results']; results=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    fs=[pool.submit(probe,x) for x in items]
    for i,f in enumerate(concurrent.futures.as_completed(fs),1):
        results.append(f.result())
        if i%50==0 or i==len(fs): print(f'progress {i}/{len(fs)}',flush=True)
results.sort(key=lambda x:x['host'])
agg={}
for r in results:
    a=agg.setdefault(r['root_domain'],{'root_domain':r['root_domain'],'ips':set(),'hosts':0,'dns_ok':0,'checks':[]})
    a['ips'].update(r['dns_ips']); a['hosts']+=1
    if r['dns_ips']: a['dns_ok']+=1
    a['checks'].extend(r['checks'])
summary=[]
for root,a in sorted(agg.items()):
    checks=a['checks']; success=[x for x in checks if 200<=int(x.get('status',0))<400]
    denied=[x for x in checks if int(x.get('status',0)) in {401,403,407,408,429}]
    server=[x for x in checks if int(x.get('status',0))>=500]
    errors=[x for x in checks if x.get('error')]
    if success: state='connected'
    elif a['dns_ok'] and (denied or server): state='reachable_denied_or_server_error'
    elif a['dns_ok'] and errors: state='dns_resolved_transport_failed'
    else: state='dns_failed'
    summary.append({'root_domain':root,'ips':sorted(a['ips']),'state':state,'host_count':a['hosts'],'dns_ok_hosts':a['dns_ok'],'successful_checks':len(success),'denied_or_server_checks':len(denied)+len(server),'transport_errors':len(errors)})
base='.audit/akshare_current_connectivity'
pathlib.Path(base+'_host_checks.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
pathlib.Path(base+'_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
from collections import Counter
print('SUMMARY',json.dumps({'roots':len(summary),'connected':sum(x['state']=='connected' for x in summary),'reachable_denied_or_server_error':sum(x['state']=='reachable_denied_or_server_error' for x in summary),'dns_resolved_transport_failed':sum(x['state']=='dns_resolved_transport_failed' for x in summary),'dns_failed':sum(x['state']=='dns_failed' for x in summary),'unique_ips':len(set(ip for x in summary for ip in x['ips']))},ensure_ascii=False))
