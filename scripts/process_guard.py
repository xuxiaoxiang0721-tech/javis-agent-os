"""Own one task's Linux descendants, including detached/adopted children."""
import ctypes,os,signal,time
from pathlib import Path

def info(pid):
    try:
        text=(Path('/proc')/str(pid)/'stat').read_text();v=text[text.rfind(')')+2:].split()
        return {'pid':int(pid),'ppid':int(v[1]),'starttime':v[19],'state':v[0]}
    except (OSError,ValueError,IndexError):return None

def table():
    result={}
    for p in Path('/proc').iterdir():
        if p.name.isdigit():
            row=info(p.name)
            if row:result[row['pid']]=row
    return result

class ProcessGuard:
    def __init__(self):
        if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
            raise RuntimeError('Linux pidfd support is required for safe task process control')
        self.parent=os.getpid();self.boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.baseline={p for p,r in table().items() if r['ppid']==self.parent}
        self.records={};self.root=None;self.root_starttime=None;self.issues=[]
        # Detached grandchildren become this runner's children if their parent exits.
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.prctl(36,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'cannot enable task child subreaper')

    def bind(self,pid):
        self.root=pid
        current=info(pid)
        self.root_starttime=current['starttime'] if current and current['ppid']==self.parent else None
        self.refresh()

    def same(self,row):
        current=info(row['pid'])
        return current if current and current['starttime']==row['starttime'] else None

    def alive(self):
        return [r for r in self.records.values() if (c:=self.same(r)) and c['state'] not in ('Z','X')]

    def refresh(self):
        snapshot=table();owned={p for p,r in self.records.items() if self.same(r)}
        # A numeric root PID alone is never ownership evidence. Actual children
        # enter below through the runner's parent relationship, even if orphaned.
        while True:
            found={p for p,r in snapshot.items() if r['ppid'] in owned or (r['ppid']==self.parent and p not in self.baseline)}
            next_owned=owned|found
            if next_owned==owned:break
            owned=next_owned
        for pid in owned:
            row=snapshot.get(pid)
            if not row or row['state'] in ('Z','X'):continue
            previous=self.records.get(pid)
            if previous and previous['starttime']==row['starttime']:continue
            try:
                fd=os.pidfd_open(pid)
                current=info(pid)
                if not current or current['starttime']!=row['starttime']:os.close(fd);continue
                if previous:os.close(previous['fd'])
                self.records[pid]={**row,'fd':fd}
            except ProcessLookupError:pass
            except OSError as exc:self.issues.append('pidfd_open_failed:'+str(pid)+':'+type(exc).__name__)

    def send(self,row,sig):
        if not self.same(row):return
        try:signal.pidfd_send_signal(row['fd'],sig)
        except ProcessLookupError:pass
        except OSError as exc:self.issues.append('signal_failed:'+str(row['pid'])+':'+type(exc).__name__)

    def stop(self):
        frozen=set()
        # Freeze the worker before its children; iterate to capture concurrent forks.
        for _ in range(8):
            self.refresh();new=[r for r in self.alive() if (r['pid'],r['starttime']) not in frozen]
            if not new:break
            new.sort(key=lambda r:r['pid']!=self.root)
            for row in new:self.send(row,signal.SIGSTOP);frozen.add((row['pid'],row['starttime']))
            time.sleep(.01)
        for row in reversed(self.alive()):self.send(row,signal.SIGTERM)
        for row in self.alive():self.send(row,signal.SIGCONT)
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            self.refresh()
            alive=self.alive()
            if not alive:break
            # A child created during termination belongs to this same task.
            for row in alive:
                if (row['pid'],row['starttime']) not in frozen:
                    self.send(row,signal.SIGTERM);frozen.add((row['pid'],row['starttime']))
            time.sleep(.025)
        deadline=time.monotonic()+1
        quiet=0
        while time.monotonic()<deadline:
            self.refresh();alive=self.alive()
            for row in alive:self.send(row,signal.SIGKILL)
            quiet=quiet+1 if not alive else 0
            if quiet>=2:break
            time.sleep(.025)
        self.refresh()
        remaining=[{'pid':r['pid'],'identity':self.boot+':'+str(r['pid'])+':'+r['starttime']} for r in self.alive()]
        return {'ok':not remaining and not self.issues,'observed_processes':len(self.records),
                'remaining':remaining,'issues':list(dict.fromkeys(self.issues)),'method':'subreaper+pidfd_descendant_cleanup'}

    def close(self):
        for row in self.records.values():
            # Popen waits for its own root; only reap adopted descendants here.
            if (row['pid'],row['starttime'])!=(self.root,self.root_starttime):
                try:os.waitpid(row['pid'],os.WNOHANG)
                except ChildProcessError:pass
            os.close(row['fd'])
