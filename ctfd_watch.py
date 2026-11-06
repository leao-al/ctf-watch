#!/usr/bin/env python3
"""
ctfd_watch — avisa quando surge desafio novo (ou notificação dos admins) num CTFd.

Só usa a biblioteca padrão do Python 3.8+. Configuração por variáveis de
ambiente ou arquivo .env no mesmo diretório (veja .env.example).

Uso:
  python3 ctfd_watch.py            # loop contínuo (systemd / tmux / docker)
  python3 ctfd_watch.py --once     # uma verificação e sai (cron)
  python3 ctfd_watch.py --test     # manda uma mensagem de teste e sai
"""
import argparse
import json
import os
import smtplib
import ssl
from email.message import EmailMessage
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

UA = "ctfd-watch/1.0"
HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------- config
def load_env(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def log(msg: str) -> None:
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


# ---------------------------------------------------------------- http
def http(method, url, headers=None, data=None, timeout=20):
    h = {"User-Agent": UA}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


class CTFdError(Exception):
    pass


class CTFd:
    def __init__(self, base, token="", cookie=""):
        self.base = base.rstrip("/")
        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            self.headers["Authorization"] = f"Token {token}"
        if cookie:
            self.headers["Cookie"] = f"session={cookie}"

    def get(self, path):
        try:
            _, body = http("GET", self.base + path, self.headers)
        except urllib.error.HTTPError as e:
            detail = e.read()[:200].decode("utf-8", "replace")
            if e.code in (401, 403):
                raise CTFdError(f"HTTP {e.code} em {path} — token/sessão inválidos ou CTF pausado/encerrado. {detail}")
            raise CTFdError(f"HTTP {e.code} em {path}: {detail}")
        except urllib.error.URLError as e:
            raise CTFdError(f"sem conexão com {self.base}: {e.reason}")
        try:
            j = json.loads(body)
        except json.JSONDecodeError:
            # CTFd redireciona para /login (HTML) quando a autenticação falha
            raise CTFdError(f"resposta não-JSON em {path} — provavelmente token expirado/inválido")
        if not j.get("success", True):
            raise CTFdError(f"API retornou erro em {path}: {j.get('errors') or j.get('message')}")
        return j.get("data", [])

    def challenge_url(self, c):
        anchor = urllib.parse.quote(f"{c.get('name', '')}-{c.get('id')}")
        return f"{self.base}/challenges#{anchor}"


# ---------------------------------------------------------------- notificadores
class Notifier:
    def __init__(self):
        self.tg_token = env("TELEGRAM_BOT_TOKEN")
        self.tg_chat = env("TELEGRAM_CHAT_ID")
        self.discord = env("DISCORD_WEBHOOK_URL")
        self.ntfy = env("NTFY_TOPIC")  # ex.: fiap-ctf-leao-8f3k2 (ou URL completa de servidor próprio)
        # WhatsApp via CallMeBot (grátis, uso pessoal)
        self.wa_phone = env("WHATSAPP_PHONE").lstrip("+")
        self.wa_key = env("CALLMEBOT_APIKEY")
        # E-mail via SMTP (ex.: Gmail com senha de app)
        self.smtp_host = env("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(env("SMTP_PORT", "465"))
        self.smtp_user = env("SMTP_USER")
        self.smtp_pass = env("SMTP_PASS").replace(" ", "")
        self.mail_to = env("EMAIL_TO") or self.smtp_user
        if not any([self.tg_token and self.tg_chat, self.discord, self.ntfy,
                    self.wa_phone and self.wa_key, self.smtp_user and self.smtp_pass]):
            sys.exit("Nenhum canal configurado. Defina NTFY_TOPIC, TELEGRAM_*, DISCORD_WEBHOOK_URL, "
                     "WHATSAPP_PHONE+CALLMEBOT_APIKEY ou SMTP_USER+SMTP_PASS.")

    def send(self, title, text, click=""):
        ok = False
        if self.tg_token and self.tg_chat:
            ok |= self._try("telegram", self._telegram, title, text)
        if self.discord:
            ok |= self._try("discord", self._discord, title, text)
        if self.ntfy:
            ok |= self._try("ntfy", self._ntfy, title, text, click)
        if self.wa_phone and self.wa_key:
            ok |= self._try("whatsapp", self._whatsapp, title, text)
        if self.smtp_user and self.smtp_pass:
            ok |= self._try("email", self._email, title, text)
        return ok

    @staticmethod
    def _try(name, fn, *args):
        try:
            fn(*args)
            return True
        except Exception as e:  # noqa: BLE001
            log(f"falha ao notificar via {name}: {e}")
            return False

    def _telegram(self, title, text):
        data = urllib.parse.urlencode({
            "chat_id": self.tg_chat,
            "text": f"{title}\n\n{text}",
            "disable_web_page_preview": "true",
        }).encode()
        http("POST", f"https://api.telegram.org/bot{self.tg_token}/sendMessage",
             {"Content-Type": "application/x-www-form-urlencoded"}, data)

    def _discord(self, title, text):
        data = json.dumps({"content": f"**{title}**\n{text}"[:2000]}).encode()
        http("POST", self.discord, {"Content-Type": "application/json"}, data)

    def _whatsapp(self, title, text):
        q = urllib.parse.urlencode({"phone": self.wa_phone, "apikey": self.wa_key,
                                    "text": f"*{title}*\n\n{text}"})
        _, body = http("GET", f"https://api.callmebot.com/whatsapp.php?{q}", timeout=30)
        low = body.decode("utf-8", "replace").lower()
        if "apikey is invalid" in low or "error" in low and "queued" not in low:
            raise RuntimeError(low[:200])

    def _email(self, title, text):
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = title, self.smtp_user, self.mail_to
        msg.set_content(text)
        ctx = ssl.create_default_context()
        if self.smtp_port == 465:
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, context=ctx, timeout=20) as s:
                s.login(self.smtp_user, self.smtp_pass)
                s.send_message(msg)
        else:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=20) as s:
                s.starttls(context=ctx)
                s.login(self.smtp_user, self.smtp_pass)
                s.send_message(msg)

    def _ntfy(self, title, text, click):
        url = self.ntfy if self.ntfy.startswith("http") else f"https://ntfy.sh/{self.ntfy}"
        h = {"Title": title.encode("ascii", "ignore").decode() or "CTFd",
             "Tags": "triangular_flag_on_post", "Priority": "high"}
        if click:
            h["Click"] = click
        http("POST", url, h, text.encode("utf-8"))


# ---------------------------------------------------------------- estado
def load_state(path: Path):
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log("estado corrompido, recriando")
    return {"initialized": False, "challenges": {}, "notifications": []}


def save_state(path: Path, state):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------- lógica
def check(api: CTFd, notifier: Notifier, state, alert_on_first_run=False):
    chals = api.get("/api/v1/challenges")
    try:
        notifs = api.get("/api/v1/notifications")
    except CTFdError as e:
        log(f"aviso: não consegui ler notificações ({e})")
        notifs = None

    first = not state["initialized"]
    known = state["challenges"]
    new = [c for c in chals if str(c.get("id")) not in known]

    if new and (not first or alert_on_first_run):
        new.sort(key=lambda c: (c.get("category", ""), c.get("value", 0)))
        lines = [f"• [{c.get('category', '?')}] {c.get('name')} — {c.get('value')} pts\n  {api.challenge_url(c)}"
                 for c in new]
        title = "🚩 Novo desafio no CTF" if len(new) == 1 else f"🚩 {len(new)} novos desafios no CTF"
        click = api.challenge_url(new[0]) if len(new) == 1 else f"{api.base}/challenges"
        notifier.send(title, "\n".join(lines), click)
        log(f"{len(new)} desafio(s) novo(s): " + ", ".join(c.get("name", "?") for c in new))
    elif first:
        log(f"primeira execução: {len(chals)} desafio(s) registrados como já vistos")

    for c in chals:
        known[str(c["id"])] = {"name": c.get("name"), "category": c.get("category"), "value": c.get("value")}

    if notifs is not None:
        seen = set(state["notifications"])
        fresh = [n for n in notifs if n.get("id") not in seen]
        if fresh and not first:
            for n in sorted(fresh, key=lambda n: n.get("id", 0)):
                notifier.send(f"📢 CTFd: {n.get('title', 'Notificação')}",
                              (n.get("content") or "")[:1500], f"{api.base}/notifications")
            log(f"{len(fresh)} notificação(ões) nova(s)")
        state["notifications"] = sorted(seen | {n.get("id") for n in notifs})

    state["initialized"] = True
    return len(new)


def main():
    load_env(HERE / ".env")
    ap = argparse.ArgumentParser(description="Monitora um CTFd e avisa sobre desafios novos.")
    ap.add_argument("--once", action="store_true", help="verifica uma vez e sai (para cron)")
    ap.add_argument("--test", action="store_true", help="envia uma notificação de teste e sai")
    ap.add_argument("--interval", type=int, default=int(env("CHECK_INTERVAL", "120")), help="segundos entre checagens")
    ap.add_argument("--state", default=env("STATE_FILE", str(HERE / "ctfd_state.json")))
    ap.add_argument("--alert-existing", action="store_true",
                    help="na primeira execução, avisar também os desafios que já existem")
    args = ap.parse_args()

    base = env("CTFD_URL")
    token, cookie = env("CTFD_TOKEN"), env("CTFD_SESSION")
    if not base or not (token or cookie):
        sys.exit("Defina CTFD_URL e CTFD_TOKEN (ou CTFD_SESSION).")

    notifier = Notifier()
    if args.test:
        ok = notifier.send("✅ ctfd_watch funcionando", f"Monitorando {base}")
        sys.exit(0 if ok else 1)

    api = CTFd(base, token, cookie)
    state_path = Path(args.state)
    state = load_state(state_path)

    # contadores de falha ficam no estado para funcionar também com --once (cron / GitHub Actions)
    fail_limit = int(env("FAIL_ALERT_AFTER", "5"))
    while True:
        try:
            check(api, notifier, state, args.alert_existing)
            if state.get("alerted_down"):
                notifier.send("✅ ctfd_watch voltou", f"Acesso a {base} normalizado.")
            state["fails"], state["alerted_down"] = 0, False
        except CTFdError as e:
            state["fails"] = state.get("fails", 0) + 1
            log(f"erro ({state['fails']}x seguidas): {e}")
            if state["fails"] >= fail_limit and not state.get("alerted_down"):
                notifier.send("⚠️ ctfd_watch com problema",
                              f"{state['fails']} falhas seguidas.\n{e}\n\nSe for login, renove CTFD_TOKEN/CTFD_SESSION.")
                state["alerted_down"] = True
        save_state(state_path, state)
        if args.once:
            break
        time.sleep(max(30, args.interval))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
