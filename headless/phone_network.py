"""Optional one-connection TCP relay through Android networking, independent of the game."""
import queue,re,shlex,subprocess,threading,time

class PhoneNetwork:
    def __init__(self,host,port,serial=None):
        if not re.fullmatch(r'[A-Za-z0-9.-]+',host):raise ValueError('Unsupported relay destination host')
        self.host=host;self.port=int(port);self.serial=serial
        self.process=None;self.local_port=None;self.remote_pid=None

    def _adb(self,*args,timeout=8):
        return subprocess.run(['adb','-s',self.serial,*args],capture_output=True,timeout=timeout,
                              creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))

    def __enter__(self):
        if self.serial is None:
            p=subprocess.run(['adb','devices'],capture_output=True,check=True,timeout=8)
            devices=[line.split()[0] for line in p.stdout.decode().splitlines()[1:]
                     if len(line.split())>=2 and line.split()[1]=='device']
            if len(devices)!=1:raise RuntimeError('Expected one connected Android device; use --serial to select it')
            self.serial=devices[0]
        command=(f'echo $$; exec /system/bin/nc -l -s 127.0.0.1 -p 28473 '
                 f'/system/bin/nc -w 5 -W 60 {shlex.quote(self.host)} {self.port}')
        try:
            self.process=subprocess.Popen(['adb','-s',self.serial,'shell','su -c '+shlex.quote(command)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            ready=queue.Queue()
            threading.Thread(target=lambda:ready.put(self.process.stdout.readline()),daemon=True).start()
            try:line=ready.get(timeout=8).strip()
            except queue.Empty:raise RuntimeError('Phone TCP relay did not start') from None
            if not line.isdigit():raise RuntimeError('Phone relay requires working root access and Android netcat')
            self.remote_pid=int(line)
            # Check the exact listener before creating an ADB forward; no connection is consumed.
            for _ in range(20):
                check=self._adb('shell',f"su -c 'cat /proc/{self.remote_pid}/cmdline'")
                if b'nc' in check.stdout and b'28473' in check.stdout:break
                if self.process.poll() is not None:raise RuntimeError('Phone relay listener exited')
                time.sleep(.1)
            else:raise RuntimeError('Phone relay listener was not ready')
            forward=self._adb('forward','--no-rebind','tcp:0','tcp:28473')
            if forward.returncode:raise RuntimeError('Could not create the phone network forward')
            self.local_port=int(forward.stdout.strip())
            return self
        except BaseException:
            self.__exit__(None,None,None);raise

    def __exit__(self,*exc):
        if self.process is not None:
            try:self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if self.remote_pid is not None:
                    check=self._adb('shell',f"su -c 'cat /proc/{self.remote_pid}/cmdline'")
                    if b'nc' in check.stdout and b'28473' in check.stdout:
                        self._adb('shell',f"su -c 'kill {self.remote_pid}'")
                self.process.terminate()
                self.process.wait(timeout=3)
            self.process.stdout.close();self.process.stderr.close()
        if self.local_port is not None:self._adb('forward','--remove',f'tcp:{self.local_port}')
