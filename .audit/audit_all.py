import akshare as ak
import inspect, json, time, traceback, socket, re, sys
from pathlib import Path
from datetime import datetime

out = Path('.audit')
public = []
for name in sorted(dir(ak)):
    if name.startswith('_'):
        continue
    try:
        obj = getattr(ak, name)
    except Exception:
        continue
    if callable(obj) and getattr(obj, '__module__', '').startswith('akshare'):
        try:
            sig = str(inspect.signature(obj))
        except Exception:
            sig = ''
        public.append({'name': name, 'signature': sig, 'module': getattr(obj, '__module__', '')})

# Only call functions whose signature has no required positional/keyword parameters.
selected = []
for item in public:
    try:
        sig = inspect.signature(getattr(ak, item['name']))
        required = [p for p in sig.parameters.values() if p.default is inspect.Parameter.empty and p.kind in (p.POSITIONAL_ONLY,p.POSITIONAL_OR_KEYWORD,p.KEYWORD_ONLY)]
        if not required:
            selected.append(item['name'])
    except Exception:
        pass

# Keep automated no-arg calls bounded; these are the interfaces most likely to be safe to probe.
# All public inventory is still saved; parameterized interfaces are reported separately.
selected = selected[:]
results=[]
url_re = re.compile(r'https?://[^\s\"\'<>]+')
def urls_from_text(text):
    vals=[]
    for u in url_re.findall(text or ''):
        vals.append(u.rstrip('.,);]'))
    return sorted(set(vals))
def domains(urls):
    out=[]
    for u in urls:
        host=re.sub(r'^https?://','',u).split('/',1)[0].split(':',1)[0]
        try: ips=sorted(set(socket.gethostbyname_ex(host)[2]))
        except Exception as e: ips=[f'DNS_ERROR:{type(e).__name__}:{e}']
        out.append({'host':host,'ips':ips})
    return out
for i,name in enumerate(selected,1):
    fn=getattr(ak,name)
    started=time.time(); status='ok'; err=''; tb=''; shape=None; columns=[]; urls=[]
    try:
        value=fn()
        shape=list(value.shape) if hasattr(value,'shape') and value.shape is not None else None
        columns=[str(x) for x in list(getattr(value,'columns',[]))[:20]] if hasattr(value,'columns') else []
        if value is None: status='empty_none'
        elif hasattr(value,'empty') and bool(value.empty): status='empty'
    except Exception as exc:
        status='error'; err=f'{type(exc).__name__}: {exc}'; tb=traceback.format_exc(limit=8)
        urls=urls_from_text(err+'\n'+tb)
        if not urls:
            try: urls=urls_from_text(inspect.getsource(fn))
            except Exception: pass
    results.append({'name':name,'status':status,'elapsed_sec':round(time.time()-started,3),'shape':shape,'columns':columns,'error':err,'urls':urls,'domains':domains(urls),'traceback':tb[-5000:]})
    print(f'[{i}/{len(selected)}] {status} {name} {results[-1]["elapsed_sec"]:.1f}s', flush=True)

payload={'generated_at':datetime.now().astimezone().isoformat(),'python':sys.version,'akshare_version':ak.__version__,'public_count':len(public),'no_required_arg_count':len(selected),'public_functions':public,'results':results}
(out/'akshare_audit.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
# compact summary
from collections import Counter
summary=Counter(x['status'] for x in results)
(out/'akshare_audit_summary.json').write_text(json.dumps({'summary':summary,'public_count':len(public),'no_required_arg_count':len(selected)},ensure_ascii=False,indent=2),encoding='utf-8')
print('SUMMARY',dict(summary))
