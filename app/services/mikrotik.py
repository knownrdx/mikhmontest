import routeros_api
import re
from ..utils.helpers import parse_address
from ..utils.crypto import decrypt_text


def get_api(router: dict):
    """Legacy: create a fresh one-off connection (no pooling)."""
    ip, port = parse_address(router.get("ip", ""))
    conn = routeros_api.RouterOsApiPool(
        ip,
        username=router.get("api_user", ""),
        password=(
            decrypt_text(router.get("api_pass_enc", ""))
            if router.get("api_pass_enc")
            else router.get("api_pass", "")
        ),
        port=port,
        plaintext_login=True,
    )
    return conn, conn.get_api()


def get_api_pooled(router: dict, session_id: str = None):
    """
    Pool-aware connection getter.

    If session_id is provided, uses the global connection pool
    (persistent, cached, auto-reconnect).
    Returns (DummyConn, api) — DummyConn.disconnect() is a no-op.

    If no session_id, falls back to legacy get_api().
    """
    if session_id:
        from .router_pool import router_pool
        return router_pool.get_api_and_conn(session_id, router)
    return get_api(router)


# -----------------------------
# Helpers
# -----------------------------
def _safe_ros_name(s: str) -> str:
    s = (s or "").strip()
    return re.sub(r"[^A-Za-z0-9_.@-]+", "_", s)


def _strip_quotes(s: str) -> str:
    return (s or "").replace('"', "").strip()


# -----------------------------
# ON-LOGIN (MikroMan-compatible, compressed single-line)
# RouterOS v6 & v7 compatible
#
# Format:
#   Line 1: :put (",expmode,shared,validity,price,sprice,lock,");
#   Line 2: compressed on-login script body
#
# Behavior:
#  - if first login (vc/up/empty comment) then:
#     1) compute expiry via temp scheduler next-run
#     2) set user comment to expiry datetime (MikroMan style)
#     3) remove temp scheduler
#     4) add /system script report
#     5) optional lock mac
# -----------------------------
def build_mikroman_on_login(
    *,
    profile: str,
    validity: str,
    exp_mode: str,
    shared_users: int,
    price: str,
    selling_price: str,
    lock_user: str,
) -> str:
    """Build MikroMan-compatible on-login script.

    Format: :put metadata line + compressed single-line script.
    Works on both RouterOS v6 and v7.
    """
    profile = _strip_quotes(profile)
    validity = _strip_quotes(validity or "30d")
    exp_mode = _strip_quotes(exp_mode or "remc")
    # Preserve price exactly — do NOT use 'or "0"' which swallows valid "0" and empty strings
    price = _strip_quotes(str(price)) if price is not None and str(price).strip() != '' else "0"
    selling_price = _strip_quotes(str(selling_price)) if selling_price is not None and str(selling_price).strip() != '' else "0"
    lock_user = _strip_quotes(lock_user or "Enable")
    shared_users = int(shared_users or 1)

    # :put line contains metadata: expmode, shared, validity, price, sprice, lock
    put_line = f':put (",{exp_mode},{shared_users},{validity},{price},{selling_price},{lock_user},");'

    # For "none" mode: permanent user — no expiry, no scheduler, minimal script
    if exp_mode == "none" or exp_mode == "0":
        script_body = ' {'
        # Lock user: bind MAC on first login
        if (lock_user or "").lower() == "enable":
            script_body += ' :local mac $"mac-address"; /ip hotspot user set mac-address=$mac [find where name=$user];'
        script_body += '}'
        return put_line + "\n" + script_body

    # Compressed on-login script (MikroMan format) — RouterOS v6 & v7 compatible
    script_body = (
        ' {:local comment [ /ip hotspot user get [/ip hotspot user find where name="$user"] comment];'
        ' :local ucode [:pic $comment 0 2];'
        ' :if ($ucode = "vc" or $ucode = "up" or $comment = "") do={'
        ' :local date [ /system clock get date ];'
        ':if ([:pick $date 4 5] = "-") do={'
        ':local arraybln {"01"="jan";"02"="feb";"03"="mar";"04"="apr";"05"="may";"06"="jun";"07"="jul";"08"="aug";"09"="sep";"10"="oct";"11"="nov";"12"="dec"};'
        ':local tgl [:pick $date 8 10];'
        ':local bulan [:pick $date 5 7];'
        ':local tahun [:pick $date 0 4];'
        ':local bln ($arraybln->$bulan);'
        ':set $date ($bln."/".$tgl."/".$tahun);};'
        ':local year [ :pick $date 7 11 ];'
        ':local month [ :pick $date 0 3 ];'
        f' /sys sch add name="$user" disable=no start-date=$date interval="{validity}";'
        ' :delay 5s;'
        ' :local exp [ /sys sch get [ /sys sch find where name="$user" ] next-run];'
        ':if ([:pick $exp 2 3] = "-") do={'
        ':local arraybln {"01"="jan";"02"="feb";"03"="mar";"04"="apr";"05"="may";"06"="jun";"07"="jul";"08"="aug";"09"="sep";"10"="oct";"11"="nov";"12"="dec"};'
        ':local tgl [:pick $exp 3 5];'
        ':local bulan [:pick $exp 0 2];'
        ':local bln ($arraybln->$bulan);'
        ':local jam [:pick $exp 11 19];'
        ':set $exp ($bln."/".$tgl." ".$jam);};'
        ':if ([:pick $exp 4 5] = "-") do={'
        ':local arraybln {"01"="jan";"02"="feb";"03"="mar";"04"="apr";"05"="may";"06"="jun";"07"="jul";"08"="aug";"09"="sep";"10"="oct";"11"="nov";"12"="dec"};'
        ':local tgl [:pick $exp 8 10];'
        ':local bulan [:pick $exp 5 7];'
        ':local tahun [:pick $exp 0 4];'
        ':local bln ($arraybln->$bulan);'
        ':local jam [:pick $exp 11 19];'
        ':set $exp ($bln."/".$tgl."/".$tahun." ".$jam);};'
        ' :local getxp [len $exp];'
        ' :if ($getxp = 15) do={'
        ' :local d [:pic $exp 0 6];'
        ' :local t [:pic $exp 7 16];'
        ' :local s ("/");'
        ' :local exp ("$d$s$year $t");'
        ' /ip hotspot user set comment="$exp" [find where name="$user"];' + '};'
        ' :if ($getxp = 8) do={'
        ' /ip hotspot user set comment="$date $exp" [find where name="$user"];' + '};'
        ' :if ($getxp > 15) do={'
        ' /ip hotspot user set comment="$exp" [find where name="$user"];' + '}; '
        ':delay 5s;'
        ' /sys sch remove [find where name="$user"];'
        ' :local mac $"mac-address";'
        ' :local time [/system clock get time ];'
        f' /system script add name="$date-|-$time-|-$user-|-{selling_price or price}-|-$address-|-$mac-|-{validity}-|-{profile}-|-$comment" owner="$month$year" source="$date" comment="mikroman";'
    )

    # Lock user: bind MAC on first login
    if (lock_user or "").lower() == "enable":
        script_body += ' [:local mac $"mac-address"; /ip hotspot user set mac-address=$mac [find where name=$user]]'

    script_body += '}}'

    return put_line + "\n" + script_body


def parse_on_login_put_line(on_login: str) -> dict:
    """Parse the :put metadata line from on-login script.

    Returns dict with keys: expmode, shared, validity, price, sprice, lock
    Example :put line: :put (",remc,20,30d,20,,Enable,");
    """
    meta = {
        'expmode': 'remc',
        'shared': '1',
        'validity': '30d',
        'price': '',
        'sprice': '',
        'lock': 'Enable',
    }

    if not on_login:
        return meta

    # Find :put line
    m = re.search(r':put\s*\("([^"]*)"\)', on_login)
    if not m:
        # Fallback: try interval= marker (old format)
        m2 = re.search(r'interval="(\d+[smhdw]+)"', on_login)
        if m2:
            meta['validity'] = m2.group(1)
        return meta

    raw = m.group(1).strip(',')
    parts = raw.split(',')

    # Map parts: expmode,shared,validity,price,sprice,lock
    if len(parts) >= 1 and parts[0]:
        meta['expmode'] = parts[0]
    if len(parts) >= 2 and parts[1]:
        meta['shared'] = parts[1]
    if len(parts) >= 3 and parts[2]:
        meta['validity'] = parts[2]
    if len(parts) >= 4:
        meta['price'] = parts[3] if parts[3] else ''
    if len(parts) >= 5:
        meta['sprice'] = parts[4] if parts[4] else ''
    if len(parts) >= 6 and parts[5]:
        meta['lock'] = parts[5]

    return meta


# -----------------------------
# Per-Profile Expiry Scheduler (MikroMan-compatible)
# RouterOS v6 & v7 compatible
#
# This creates a scheduler that runs every 2m14s
# and checks all users of a specific profile for expiry.
# When expired: remove user + remove active session.
# -----------------------------
def build_per_profile_expiry_script(profile_name: str, exp_mode: str = "remc") -> str:
    """Build expiry scheduler on-event script for a specific profile.

    MikroMan format — per-profile scheduler.
    Compatible with RouterOS v6 and v7.

    Modes:
      remc   = Remove & Record (remove user + log to /system script)
      rem    = Remove (remove user, no log)
      notice = Notice (set comment to EXPIRED, don't remove)
      notic  = Notice & Record (set comment to EXPIRED + log)
    """
    profile_name = _strip_quotes(profile_name)
    exp_mode = (exp_mode or "remc").strip().lower()

    # Common preamble: date/time parsing, find expired users
    preamble = (
        ':local dateint do={'
        ':local montharray ( "jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec" );'
        ':local days [ :pick $d 4 6 ];'
        ':local month [ :pick $d 0 3 ];'
        ':local year [ :pick $d 7 11 ];'
        ':local monthint ([ :find $montharray $month]);'
        ':local month ($monthint + 1);'
        ':if ( [len $month] = 1) do={'
        ':local zero ("0");'
        ':return [:tonum ("$year$zero$month$days")];'
        '} else={'
        ':return [:tonum ("$year$month$days")];}};'
        ' :local timeint do={ :local hours [ :pick $t 0 2 ]; :local minutes [ :pick $t 3 5 ]; :return ($hours * 60 + $minutes) ; };'
        ' :local date [ /system clock get date ];'
        ':if ([:pick $date 4 5] = "-") do={'
        ':local arraybln {"01"="jan";"02"="feb";"03"="mar";"04"="apr";"05"="may";"06"="jun";"07"="jul";"08"="aug";"09"="sep";"10"="oct";"11"="nov";"12"="dec"};'
        ':local tgl [:pick $date 8 10];'
        ':local bulan [:pick $date 5 7];'
        ':local tahun [:pick $date 0 4];'
        ':local bln ($arraybln->$bulan);'
        ':set $date ($bln."/".$tgl."/".$tahun);};'
        ' :local time [ /system clock get time ];'
        ' :local today [$dateint d=$date] ;'
        ' :local curtime [$timeint t=$time] ;'
        f' :foreach i in [ /ip hotspot user find where profile="{profile_name}" ] do={{'
        ' :local comment [ /ip hotspot user get $i comment];'
        ' :local name [ /ip hotspot user get $i name];'
        ' :local gettime [:pic $comment 12 20];'
        ' :if ([:pic $comment 3] = "/" and [:pic $comment 6] = "/") do={'
        ':local expd [$dateint d=$comment] ;'
        ' :local expt [$timeint t=$gettime] ;'
        ' :if (($expd < $today and $expt < $curtime) or ($expd < $today and $expt > $curtime) or ($expd = $today and $expt < $curtime)) do={'
    )

    # Action block depends on mode
    if exp_mode == "remc":
        # Remove & Record: log + remove user + remove active
        action = (
            ' :local d [/system clock get date];'
            ' :local t [/system clock get time];'
            ' :local mac ""; :local ip "";'
            ' :do { :set $mac [/ip hotspot active get [/ip hotspot active find where user=$name] mac-address] } on-error={};'
            ' :do { :set $ip  [/ip hotspot active get [/ip hotspot active find where user=$name] address] } on-error={};'
            ' :local prof [ /ip hotspot user get $i profile];'
            f' /system script add name=("$d-|-$t-|-$name-|-EXPIRE-|-".$ip."-|-".$mac."-|-".$prof."-|-".$comment) source=$d comment="mikroman-expire";'
            ' [ /ip hotspot user remove $i ];'
            ' [ /ip hotspot active remove [find where user=$name] ];'
        )
    elif exp_mode == "rem":
        # Remove only: remove user + remove active, no log
        action = (
            ' [ /ip hotspot user remove $i ];'
            ' [ /ip hotspot active remove [find where user=$name] ];'
        )
    elif exp_mode == "notice":
        # Notice only: disable user + set comment, don't remove
        action = (
            ' /ip hotspot user set disabled=yes comment="EXPIRED" [find where name=$name];'
            ' [ /ip hotspot active remove [find where user=$name] ];'
        )
    elif exp_mode == "notic":
        # Notice & Record: disable + log
        action = (
            ' :local d [/system clock get date];'
            ' :local t [/system clock get time];'
            ' :local mac ""; :local ip "";'
            ' :do { :set $mac [/ip hotspot active get [/ip hotspot active find where user=$name] mac-address] } on-error={};'
            ' :do { :set $ip  [/ip hotspot active get [/ip hotspot active find where user=$name] address] } on-error={};'
            ' :local prof [ /ip hotspot user get $i profile];'
            f' /system script add name=("$d-|-$t-|-$name-|-EXPIRE-|-".$ip."-|-".$mac."-|-".$prof."-|-".$comment) source=$d comment="mikroman-expire";'
            ' /ip hotspot user set disabled=yes comment="EXPIRED" [find where name=$name];'
            ' [ /ip hotspot active remove [find where user=$name] ];'
        )
    else:
        action = ''

    return preamble + action + '}}}}'


def build_global_expiry_delete_script() -> str:
    """Legacy global expiry script (all profiles).

    Kept for backward compatibility. New profiles use per-profile schedulers.
    """
    return r''':local montharray ("jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec");

:local dateint do={
  :local d $1;
  :local days [:pick $d 4 6];
  :local mon [:pick $d 0 3];
  :local yr  [:pick $d 7 11];
  :local mi ([:find $montharray $mon] + 1);
  :local m $mi;
  :if ([:len $m] = 1) do={ :set $m ("0".$m); }
  :return [:tonum ($yr.$m.$days)];
};

:local timeint do={
  :local t $1;
  :local hh [:pick $t 0 2];
  :local mm [:pick $t 3 5];
  :return ([:tonum $hh] * 60 + [:tonum $mm]);
};

# normalize system date if ISO (v7)
:local sysDate [/system clock get date];
:if ([:pick $sysDate 4 5] = "-") do={
  :local map {"01"="jan";"02"="feb";"03"="mar";"04"="apr";"05"="may";"06"="jun";"07"="jul";"08"="aug";"09"="sep";"10"="oct";"11"="nov";"12"="dec"};
  :local dd [:pick $sysDate 8 10];
  :local mo [:pick $sysDate 5 7];
  :local yy [:pick $sysDate 0 4];
  :set $sysDate (($map->$mo)."/".$dd."/".$yy);
};
:local sysTime [/system clock get time];
:local today [$dateint $sysDate];
:local curm  [$timeint $sysTime];

:foreach i in [/ip hotspot user find] do={

  :local skip false;

  :local name [/ip hotspot user get $i name];
  :local prof [/ip hotspot user get $i profile];
  :local comm [/ip hotspot user get $i comment];

  :if ([:len $comm] < 16) do={ :set $skip true; }

  :local norm $comm;

  # ISO comment -> MikroMan normalize
  :if (!$skip && ([:pick $norm 4 5] = "-" && [:pick $norm 7 8] = "-")) do={
    :local map {"01"="jan";"02"="feb";"03"="mar";"04"="apr";"05"="may";"06"="jun";"07"="jul";"08"="aug";"09"="sep";"10"="oct";"11"="nov";"12"="dec"};
    :local yy [:pick $norm 0 4];
    :local mo [:pick $norm 5 7];
    :local dd [:pick $norm 8 10];
    :local tt [:pick $norm 11 19];
    :set $norm (($map->$mo)."/".$dd."/".$yy." ".$tt);
  };

  # must be mon/DD/YYYY ...
  :if (!$skip) do={
    :if ([:pick $norm 3 4] != "/") do={ :set $skip true; }
    :if ([:pick $norm 6 7] != "/") do={ :set $skip true; }
  }

  :if (!$skip) do={
    :local expDate [:pick $norm 0 11];
    :local expTime [:pick $norm 12 20];

    :local expd [$dateint $expDate];
    :local expt [$timeint $expTime];

    :if (($expd < $today) || ($expd = $today && $expt < $curm)) do={

      # REPORT BEFORE DELETE
      :local d [/system clock get date];
      :local t [/system clock get time];
      :local mac "";
      :local ip  "";
      :do { :set $mac [/ip hotspot active get [/ip hotspot active find where user=$name] mac-address] } on-error={};
      :do { :set $ip  [/ip hotspot active get [/ip hotspot active find where user=$name] address] } on-error={};

      /system script add name=("$d-|-$t-|-$name-|-EXPIRE-|-".$ip."-|-".$mac."-|-".$prof."-|-".$norm) source=$d comment="mikroman-expire";

      /ip hotspot active remove [find where user=$name];
      /ip hotspot user remove $i;
    }
  }
}'''


def ensure_per_profile_expiry_scheduler(api, profile_name: str, *, interval: str = "2m14s", exp_mode: str = "remc"):
    """Upsert per-profile expiry scheduler on the router.

    Creates:
      - /system scheduler name="<profile>" interval=<interval>
        comment="mikroman monitoring Mode"
        on-event = per-profile expiry script (inline)

    MikroMan-compatible approach: scheduler on-event contains the full script.
    """
    profile_name = _strip_quotes(profile_name)
    scheduler_name = profile_name

    sched_res = api.get_resource("/system/scheduler")
    on_event = build_per_profile_expiry_script(profile_name, exp_mode=exp_mode)

    # upsert scheduler
    try:
        exs = sched_res.get(name=scheduler_name)
    except Exception:
        exs = [s for s in sched_res.get() if s.get("name") == scheduler_name]

    if exs:
        eid = exs[0].get(".id") or exs[0].get("id")
        sched_res.set(id=eid, name=scheduler_name, interval=interval, on_event=on_event, comment="mikroman monitoring Mode", disabled="no")
    else:
        sched_res.add(name=scheduler_name, interval=interval, on_event=on_event, comment="mikroman monitoring Mode", disabled="no")


def ensure_global_expiry_scheduler(api, *, interval: str = "2m14s"):
    """Upserts legacy global expiry scheduler.

    Kept for backward compatibility with existing setups.
    """
    script_name = "mkh-expire-all"
    scheduler_name = "mkh-expire-all"

    script_res = api.get_resource("/system/script")
    sched_res = api.get_resource("/system/scheduler")

    source = build_global_expiry_delete_script()

    # upsert script
    try:
        existing = script_res.get(name=script_name)
    except Exception:
        existing = [s for s in script_res.get() if s.get("name") == script_name]

    if existing:
        sid = existing[0].get(".id") or existing[0].get("id")
        script_res.set(id=sid, name=script_name, source=source, comment="mikroman")
    else:
        script_res.add(name=script_name, source=source, comment="mikroman")

    on_event = f'/system script run "{script_name}"'

    # upsert scheduler
    try:
        exs = sched_res.get(name=scheduler_name)
    except Exception:
        exs = [s for s in sched_res.get() if s.get("name") == scheduler_name]

    if exs:
        eid = exs[0].get(".id") or exs[0].get("id")
        sched_res.set(id=eid, name=scheduler_name, interval=interval, on_event=on_event, disabled="no")
    else:
        sched_res.add(name=scheduler_name, interval=interval, on_event=on_event, disabled="no")


# -----------------------------
# List helpers (for admin.py imports)
# -----------------------------
def list_hotspot_user_profiles(api):
    return api.get_resource("/ip/hotspot/user/profile").get()


def list_ip_pools(api):
    pools = api.get_resource("/ip/pool").get()
    return [p.get("name") for p in pools if p.get("name")]


def list_parent_queues(api):
    names = set()
    try:
        for q in api.get_resource("/queue/tree").get():
            if q.get("name"):
                names.add(q["name"])
    except Exception:
        pass
    try:
        for q in api.get_resource("/queue/simple").get():
            if q.get("name"):
                names.add(q["name"])
    except Exception:
        pass
    return sorted(names)


def get_hotspot_user_profile_by_name(api, name: str):
    name = (name or "").strip()
    if not name:
        return None

    res = api.get_resource("/ip/hotspot/user/profile")
    try:
        items = res.get(name=name)
    except Exception:
        items = [p for p in res.get() if p.get("name") == name]
    return items[0] if items else None


# -----------------------------
# Profile CRUD (for admin.py)
# - add/update profile
# - set on-login script (MikroMan format with :put metadata)
# - ensure per-profile expiry scheduler
# - also maintain legacy global expiry scheduler
# -----------------------------
def add_hotspot_user_profile(
    api,
    *,
    name: str,
    address_pool: str = "none",
    shared_users: int = 1,
    rate_limit: str = "",
    parent_queue: str = "none",
    exp_mode: str = "remc",
    validity: str = "30d",
    price: str = "",
    selling_price: str = "",
    lock_user: str = "Enable",
    expiry_interval: str = "2m14s",
):
    name = _safe_ros_name((name or "").strip().replace(" ", ""))
    if not name:
        raise ValueError("Profile name is required")

    # lock user => force shared-users=1
    if (lock_user or "").lower() == "enable":
        shared_users = 1

    # Preserve price exactly as user entered — only default to "0" if truly None
    price_val = str(price) if price is not None and str(price).strip() != '' else "0"
    sprice_val = str(selling_price) if selling_price is not None and str(selling_price).strip() != '' else "0"

    on_login = build_mikroman_on_login(
        profile=name,
        validity=validity,
        exp_mode=exp_mode,
        shared_users=int(shared_users),
        price=price_val,
        selling_price=sprice_val,
        lock_user=lock_user,
    )

    payload = {
        "name": name,
        "shared-users": str(int(shared_users)),
        "address-pool": address_pool or "none",
        "parent-queue": parent_queue or "none",
        "on-login": on_login,
    }

    # IMPORTANT: don't send empty rate-limit (can cause !empty)
    if rate_limit:
        payload["rate-limit"] = rate_limit

    api.get_resource("/ip/hotspot/user/profile").add(**payload)

    # Create per-profile expiry scheduler (all modes except 'none')
    if exp_mode and exp_mode not in ("none", "0"):
        ensure_per_profile_expiry_scheduler(api, name, interval=expiry_interval, exp_mode=exp_mode)


def update_hotspot_user_profile(
    api,
    *,
    profile_id: str,
    name: str,
    address_pool: str = "none",
    shared_users: int = 1,
    rate_limit: str = "",
    parent_queue: str = "none",
    exp_mode: str = "remc",
    validity: str = "30d",
    price: str = "",
    selling_price: str = "",
    lock_user: str = "Enable",
    expiry_interval: str = "2m14s",
):
    if not profile_id:
        raise ValueError("Profile id is required")

    name = _safe_ros_name((name or "").strip().replace(" ", ""))
    if not name:
        raise ValueError("Profile name is required")

    if (lock_user or "").lower() == "enable":
        shared_users = 1

    # Preserve price exactly as user entered — only default to "0" if truly None/empty
    price_val = str(price) if price is not None and str(price).strip() != '' else "0"
    sprice_val = str(selling_price) if selling_price is not None and str(selling_price).strip() != '' else "0"

    on_login = build_mikroman_on_login(
        profile=name,
        validity=validity,
        exp_mode=exp_mode,
        shared_users=int(shared_users),
        price=price_val,
        selling_price=sprice_val,
        lock_user=lock_user,
    )

    payload = {
        "name": name,
        "shared-users": str(int(shared_users)),
        "address-pool": address_pool or "none",
        "parent-queue": parent_queue or "none",
        "on-login": on_login,
    }

    if rate_limit:
        payload["rate-limit"] = rate_limit

    api.get_resource("/ip/hotspot/user/profile").set(id=profile_id, **payload)

    # Update per-profile expiry scheduler (all modes except 'none')
    if exp_mode and exp_mode not in ("none", "0"):
        ensure_per_profile_expiry_scheduler(api, name, interval=expiry_interval, exp_mode=exp_mode)


# -----------------------------
# IP/MAC Binding (Hotspot Bypass)
# -----------------------------
def list_ip_bindings(api) -> list:
    """Return all /ip/hotspot/ip-binding entries."""
    try:
        return api.get_resource('/ip/hotspot/ip-binding').get()
    except Exception:
        return []


def add_ip_binding(api, *, mac_address: str = '', ip_address: str = '',
                   binding_type: str = 'bypassed', comment: str = '') -> None:
    """Add an IP/MAC binding entry. type='bypassed' skips the login page."""
    payload = {'type': binding_type}
    if mac_address:
        payload['mac-address'] = mac_address
    if ip_address:
        payload['address'] = ip_address
    if comment:
        payload['comment'] = comment
    api.get_resource('/ip/hotspot/ip-binding').add(**payload)


def delete_ip_binding(api, binding_id: str) -> None:
    """Delete an IP/MAC binding by id."""
    api.get_resource('/ip/hotspot/ip-binding').remove(id=binding_id)


# -----------------------------
# Optional: export logs as JSONL (kept from your original)
# -----------------------------
def export_router_logs(api, *, out_path: str, include_login: bool = True, include_expire: bool = True):
    import json

    res = api.get_resource("/system/script")
    items = res.get()

    wanted = set()
    if include_login:
        wanted.add("mikroman")
    if include_expire:
        wanted.add("mikroman-expire")

    logs = [it for it in items if (it.get("comment") or "").strip() in wanted]

    with open(out_path, "w", encoding="utf-8") as f:
        for row in logs:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    return {"count": len(logs), "path": out_path}


# =============================================
# BRIDGE PORT LOCK / UNLOCK
# =============================================

def detect_ros_version(api):
    """
    Detect RouterOS major version (6 or 7).
    Returns dict: {'raw': '7.12.1', 'major': 7}
    """
    try:
        res = api.get_resource('/system/resource')
        info = res.get()
        if info:
            ver_str = info[0].get('version', '')
            # version looks like "7.12.1 (stable)" or "6.49.10 (long-term)"
            import re
            m = re.match(r'(\d+)', ver_str)
            major = int(m.group(1)) if m else 0
            return {'raw': ver_str, 'major': major}
    except Exception:
        pass
    # Fallback: try to detect via date format (v7 uses yyyy-mm-dd, v6 uses mon/dd/yyyy)
    try:
        clock = api.get_resource('/system/clock')
        clock_data = clock.get()
        if clock_data:
            date_str = clock_data[0].get('date', '')
            # v7: "2024-01-15", v6: "jan/15/2024"
            if len(date_str) >= 4 and date_str[4:5] == '-':
                return {'raw': 'unknown-v7-format', 'major': 7}
            else:
                return {'raw': 'unknown-v6-format', 'major': 6}
    except Exception:
        pass
    return {'raw': 'unknown', 'major': 0}


def scan_bridges_and_ports(api):
    """
    Scan router to detect:
    - RouterOS version (v6 or v7)
    - All bridges and their ports
    - Which bridge has hotspot server (/ip/hotspot)
    - Which bridge has DHCP server (/ip/dhcp-server)

    Returns dict with full bridge/port info + ros_version for UI.
    """
    # Detect OS version first
    ros_ver = detect_ros_version(api)

    bridges_raw = api.get_resource('/interface/bridge').get()
    ports_raw = api.get_resource('/interface/bridge/port').get()
    hs_raw = api.get_resource('/ip/hotspot').get()
    dhcp_raw = api.get_resource('/ip/dhcp-server').get()

    # Map: bridge_name -> hotspot server name
    hs_bridges = {}
    for hs in hs_raw:
        iface = hs.get('interface', '')
        if iface:
            hs_bridges[iface] = hs.get('name', '')

    # Map: bridge_name -> dhcp server name
    dhcp_bridges = {}
    for ds in dhcp_raw:
        iface = ds.get('interface', '')
        if iface:
            dhcp_bridges[iface] = ds.get('name', '')

    # Build bridge list with ports
    bridges = []
    for br in bridges_raw:
        br_name = br.get('name', '')
        # Collect ports for this bridge
        ports = []
        for p in ports_raw:
            if p.get('bridge', '') == br_name:
                ports.append({
                    'interface': p.get('interface', ''),
                    '.id': p.get('.id', ''),
                    'bridge': br_name,
                    'disabled': (p.get('disabled', 'false') == 'true'),
                })

        btype = 'other'
        server_name = ''
        if br_name in hs_bridges:
            btype = 'hotspot'
            server_name = hs_bridges[br_name]
        elif br_name in dhcp_bridges:
            btype = 'dhcp'
            server_name = dhcp_bridges[br_name]

        bridges.append({
            'name': br_name,
            '.id': br.get('.id', ''),
            'type': btype,
            'server': server_name,
            'ports': ports,
        })

    return {
        'bridges': bridges,
        'ros_version': ros_ver,
    }



def get_port_lock_config(db, router_id):
    """Get saved port lock config from MongoDB."""
    return db.port_lock_config.find_one({'router_id': router_id})


def save_port_lock_config(db, router_id, scan_data, excluded_ports=None,
                         selected_hotspot_bridges=None, selected_free_bridges=None):
    """
    Save port lock config with USER-SELECTED bridge roles.

    Args:
        selected_hotspot_bridges: list of bridge names chosen as hotspot targets
        selected_free_bridges: list of bridge names chosen as free/DHCP (unlock targets)
        excluded_ports: interfaces to skip

    Ports from free bridges are distributed EQUALLY across hotspot bridges
    so no single bridge gets overloaded (prevents lag with 3-4+ users).
    Each port remembers its own lock_bridge and unlock_bridge.
    """
    excluded = set(excluded_ports or [])
    bridges = scan_data.get('bridges', [])

    # Use user selection if provided, else fall back to auto-detect
    if selected_hotspot_bridges:
        hotspot_bridges = list(selected_hotspot_bridges)
    else:
        hotspot_bridges = [b['name'] for b in bridges if b['type'] == 'hotspot']

    if selected_free_bridges:
        free_bridges = list(selected_free_bridges)
    else:
        free_bridges = [b['name'] for b in bridges if b['type'] != 'hotspot']

    # Must have at least one hotspot bridge
    if not hotspot_bridges:
        return None

    # Collect all movable ports ONLY from user-selected free bridges (not all non-hotspot)
    free_set = set(free_bridges)
    movable_ports = []
    for br in bridges:
        # Only collect ports from explicitly selected free bridges
        if br['name'] not in free_set:
            continue
        for p in br.get('ports', []):
            iface = p.get('interface', '')
            if iface in excluded:
                continue
            movable_ports.append({
                'interface': iface,
                'unlock_bridge': br['name'],
            })

    # EQUAL DISTRIBUTION: distribute ports round-robin across hotspot bridges
    # e.g. 1 free + 2 hotspot → ports split equally across both hotspot bridges
    # e.g. 2 free + 1 hotspot → all ports from both free bridges go to the 1 hotspot
    # e.g. 2 free + 2 hotspot → equal round-robin split
    # e.g. 3 free + 4 hotspot → equal round-robin split
    port_map = []
    hs_count = len(hotspot_bridges)
    for idx, pm in enumerate(movable_ports):
        target_hs = hotspot_bridges[idx % hs_count]
        port_map.append({
            'interface': pm['interface'],
            'unlock_bridge': pm['unlock_bridge'],
            'lock_bridge': target_hs,
        })

    doc = {
        'router_id': router_id,
        'hotspot_bridges': hotspot_bridges,
        'free_bridges': free_bridges,
        'excluded_ports': list(excluded),
        'port_map': port_map,
        'ros_major': scan_data.get('ros_version', {}).get('major', 0),
        'ros_version_raw': scan_data.get('ros_version', {}).get('raw', ''),
    }
    db.port_lock_config.replace_one({'router_id': router_id}, doc, upsert=True)
    return doc


def delete_port_lock_config(db, router_id):
    """Delete saved config."""
    db.port_lock_config.delete_one({'router_id': router_id})


def detect_lock_state(api, config):
    """
    Check current state by comparing port locations vs config.
    locked = all mapped ports are in their lock_bridge
    unlocked = all mapped ports are in their unlock_bridge
    """
    port_map = config.get('port_map', [])
    excluded = set(config.get('excluded_ports', []))
    if not port_map:
        return 'unknown'

    all_ports = api.get_resource('/interface/bridge/port').get()

    # Build current location map: interface -> bridge
    current = {}
    for p in all_ports:
        current[p.get('interface', '')] = p.get('bridge', '')

    in_lock = 0
    in_unlock = 0
    total = 0

    for pm in port_map:
        iface = pm['interface']
        if iface in excluded:
            continue
        cur_br = current.get(iface, '')
        total += 1
        if cur_br == pm['lock_bridge']:
            in_lock += 1
        elif cur_br == pm['unlock_bridge']:
            in_unlock += 1

    if total == 0:
        return 'unknown'
    if in_lock == total:
        return 'locked'
    if in_unlock == total:
        return 'unlocked'
    return 'mixed'


def port_lock_action(api, config, action):
    """
    Lock/Unlock ports.

    Strategy:
    1. Try running the RouterOS script (fast, reliable)
    2. If script not found or fails, execute commands directly via API (works on both v6/v7)
    """
    port_map = config.get('port_map', [])
    if not port_map:
        return {'ok': False, 'error': 'Not configured'}

    script_name = 'mikroman-lock' if action == 'lock' else 'mikroman-unlock'

    # ----- Attempt 1: Run saved script -----
    script_ok = False
    try:
        scripts_res = api.get_resource('/system/script')
        existing = scripts_res.get()
        found = [s for s in existing if s.get('name') == script_name]
        if found:
            sid = found[0].get('.id', '')
            # Try multiple run methods for v6/v7 compat
            try:
                scripts_res.call('run', {'.id': sid})
                script_ok = True
            except Exception:
                pass
            if not script_ok:
                try:
                    api.get_binary_resource('/system/script').call(
                        'run',
                        {'.id': sid.encode() if isinstance(sid, str) else sid}
                    )
                    script_ok = True
                except Exception:
                    pass
            if not script_ok:
                try:
                    api.get_binary_resource('/system/script').call(
                        'run',
                        {'number': script_name.encode()}
                    )
                    script_ok = True
                except Exception:
                    pass
    except Exception:
        pass

    # ----- Attempt 2: Direct API commands (fallback for v6 or if script missing) -----
    if not script_ok:
        try:
            bridge_port_res = api.get_resource('/interface/bridge/port')
            import time as _time

            for pm in port_map:
                iface = pm['interface']
                target = pm['lock_bridge'] if action == 'lock' else pm['unlock_bridge']

                # Remove port from current bridge
                try:
                    current_ports = bridge_port_res.get(interface=iface)
                    for cp in current_ports:
                        pid = cp.get('.id') or cp.get('id')
                        if pid:
                            bridge_port_res.remove(id=pid)
                except Exception:
                    # Fallback: try find-based removal
                    try:
                        all_ports = bridge_port_res.get()
                        for cp in all_ports:
                            if cp.get('interface') == iface:
                                pid = cp.get('.id') or cp.get('id')
                                if pid:
                                    bridge_port_res.remove(id=pid)
                    except Exception:
                        pass

                _time.sleep(0.5)

                # Add port to target bridge
                try:
                    bridge_port_res.add(interface=iface, bridge=target)
                except Exception:
                    pass

                _time.sleep(0.2)

            script_ok = True
        except Exception as e:
            return {'ok': False, 'error': f'Direct API commands failed: {e}'}

    import time
    time.sleep(1)

    state = detect_lock_state(api, config)
    method = 'script' if script_ok else 'direct-api'
    return {
        'ok': True,
        'state': state,
        'detail': f'{action.title()} executed via {method} (state: {state})',
    }


def ensure_port_lock_scripts(api, config):
    """
    Create lock/unlock scripts on the router.

    Handles RouterOS v6 and v7 differences:
    - v6: policy field uses different format, script.add may reject certain params
    - v7: policy='read,write,test' works fine

    Detection: uses ros_major from config (set during scan).
    If unknown, tries v7 first then v6 fallback.

    The script body itself uses only commands that work on BOTH v6 and v7:
    - /interface bridge port remove [find interface="X"]
    - /interface bridge port add interface="X" bridge="Y"
    - :delay for timing between operations
    - :do { } on-error={} for error handling
    """
    port_map = config.get('port_map', [])
    if not port_map:
        return []

    ros_major = config.get('ros_major', 0)

    # Build script bodies using syntax that works on both v6 and v7
    def build_script_body(action_name, port_mappings, key):
        """Build RouterOS script body. key = 'lock_bridge' or 'unlock_bridge'."""
        lines = []
        lines.append(f'# MikroMan {action_name} Script')
        lines.append(f':log info "MikroMan: {action_name} ports..."')
        for pm in port_mappings:
            iface = pm['interface']
            target = pm[key]
            # Remove: find by interface name and remove (works v6+v7)
            lines.append(f':do {{ /interface bridge port remove [find interface="{iface}"] }} on-error={{}}')
            lines.append(':delay 1s')
            # Add to target bridge
            lines.append(f':do {{ /interface bridge port add interface="{iface}" bridge="{target}" }} on-error={{}}')
            lines.append(':delay 500ms')
        lines.append(f':log info "MikroMan: {action_name} complete"')
        return "\r\n".join(lines)

    lock_body = build_script_body('Lock', port_map, 'lock_bridge')
    unlock_body = build_script_body('Unlock', port_map, 'unlock_bridge')

    scripts_res = api.get_resource('/system/script')

    # Get all existing scripts once
    try:
        existing = scripts_res.get()
    except Exception:
        existing = []

    created = []

    for sname, sbody in [('mikroman-lock', lock_body), ('mikroman-unlock', unlock_body)]:
        # Step 1: Remove existing script with this name
        for s in existing:
            if s.get('name') == sname:
                try:
                    sid = s.get('.id') or s.get('id')
                    if sid:
                        scripts_res.remove(id=sid)
                except Exception:
                    # v6 fallback: try binary resource
                    try:
                        bres = api.get_binary_resource('/system/script')
                        sid = s.get('.id') or s.get('id')
                        if sid:
                            sid_b = sid.encode() if isinstance(sid, str) else sid
                            bres.call('remove', {'.id': sid_b})
                    except Exception:
                        pass

        # Step 2: Create new script — different strategies for v6 vs v7
        add_ok = False

        if ros_major >= 7 or ros_major == 0:
            # Try v7 first (or unknown)
            try:
                scripts_res.add(name=sname, source=sbody, policy='read,write,test')
                add_ok = True
            except Exception:
                pass

        if not add_ok:
            # v6 style: try without policy first (most reliable on v6)
            try:
                scripts_res.add(name=sname, source=sbody)
                add_ok = True
            except Exception:
                pass

        if not add_ok:
            # v6 with explicit policy formats
            for pol in ['read,write,policy,test', 'ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon']:
                try:
                    scripts_res.add(name=sname, source=sbody, policy=pol)
                    add_ok = True
                    break
                except Exception:
                    pass

        if not add_ok:
            # Last resort: use binary resource (some v6 builds need this)
            try:
                bres = api.get_binary_resource('/system/script')
                params = {
                    'name': sname.encode(),
                    'source': sbody.encode(),
                }
                bres.call('add', params)
                add_ok = True
            except Exception:
                pass

        if add_ok:
            created.append(sname)
        else:
            created.append(f'{sname} (FAILED)')

    return created


# =============================================
# VPN MANAGER — PPP SECRETS, PROFILES, NAT
# =============================================

def list_ppp_secrets(api) -> list:
    try:
        return api.get_resource('/ppp/secret').get()
    except Exception:
        return []

def add_ppp_secret(api, *, name, password, service='any',
                   local_address='', remote_address='', profile='default', comment=''):
    payload = {'name': name, 'password': password, 'service': service, 'profile': profile}
    if local_address:  payload['local-address'] = local_address
    if remote_address: payload['remote-address'] = remote_address
    if comment:        payload['comment'] = comment
    api.get_resource('/ppp/secret').add(**payload)

def update_ppp_secret(api, *, secret_id, name=None, password=None, service=None,
                      local_address=None, remote_address=None, profile=None, comment=None):
    payload = {'id': secret_id}
    if name is not None:           payload['name'] = name
    if password is not None:       payload['password'] = password
    if service is not None:        payload['service'] = service
    if local_address is not None:  payload['local-address'] = local_address
    if remote_address is not None: payload['remote-address'] = remote_address
    if profile is not None:        payload['profile'] = profile
    if comment is not None:        payload['comment'] = comment
    api.get_resource('/ppp/secret').set(**payload)

def delete_ppp_secret(api, secret_id: str):
    api.get_resource('/ppp/secret').remove(id=secret_id)

def list_ppp_profiles(api) -> list:
    try:
        return api.get_resource('/ppp/profile').get()
    except Exception:
        return []

def list_nat_rules(api, *, chain='dstnat') -> list:
    try:
        rules = api.get_resource('/ip/firewall/nat').get()
        return [r for r in rules if r.get('chain') == chain]
    except Exception:
        return []

def add_nat_rule(api, *, protocol, dst_port, to_address, to_port,
                 comment='', chain='dstnat', action='dst-nat'):
    payload = {
        'chain': chain, 'action': action, 'protocol': protocol,
        'dst-port': dst_port, 'to-ports': to_port,
    }
    if to_address:
        payload['to-addresses'] = to_address
    if comment:
        payload['comment'] = comment
    api.get_resource('/ip/firewall/nat').add(**payload)

def toggle_nat_rule(api, rule_id: str, disabled: bool):
    api.get_resource('/ip/firewall/nat').set(id=rule_id, disabled='yes' if disabled else 'no')

def delete_nat_rule(api, rule_id: str):
    api.get_resource('/ip/firewall/nat').remove(id=rule_id)


def list_ppp_active(api) -> list:
    try:
        return api.get_resource('/ppp/active').get()
    except Exception:
        return []
