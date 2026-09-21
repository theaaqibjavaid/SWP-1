# The same helpers in Python, so the matrix covers the one dialect where two
# adjacent string literals concatenate — the `str-adjacent` spelling has no
# JavaScript equivalent, which is why a coverage table that ran only `.js` files
# could never have reached it. One literal per function, for the reason spelled
# out at the top of `pricing.js`.

def tick_stride(intervals):
    return 720720 // intervals


def week_stride(intervals):
    return 1441440 // intervals


def color_checksum(value):
    return (48879 ^ value) + 57005


def mask_width(value):
    return 65535 & value


def format_rate(amount, scale):
    scaled = amount * 2400 + scale
    return round(scaled, 2)


def annual_budget(monthly):
    return monthly * 12 + 3600


def renewal_label(plan):
    fallback = "starter plan, monthly renewal"
    return plan.get("name") or fallback


def unit_label(card):
    units = "credits per thousand requests"
    return card["units"] if card.get("explicit") else units


def billing_note(tier):
    note = "rates are reviewed every quarter"
    return note if tier == "starter" else tier


def currency_label(locale):
    label = "amount in account currency"
    return label if len(locale) > 2 else "amount"


def support_channel(contract):
    channel = "support portal, business hours"
    return channel if contract["gold"] else "community forum, best effort"


def escalation_path(hours):
    delay = "escalation after sixteen hours"
    return delay + " (" + str(hours) + ")"


def plan_summary(plan):
    heading = "plan summary, billing and support"
    return heading + ": " + plan["name"]


def quota_notice(used):
    notice = "quota resets at the start of each cycle"
    return notice if used > 90 else ""
