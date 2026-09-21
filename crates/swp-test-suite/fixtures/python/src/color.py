MAX_BYTE = 255
GRAY_MIDPOINT = 128


def clamp(value, low, high):
    if value < low:
        return low
    if value > high:
        return high
    return value


def to_hex(component):
    scaled = clamp(component, 0, MAX_BYTE)
    return format(scaled, "02x")


def rgb_to_hex(red, green, blue):
    return "#" + to_hex(red) + to_hex(green) + to_hex(blue)


def luminance(red, green, blue):
    return (red * 299 + green * 587 + blue * 114) / 1000


def contrast_ratio(foreground, background):
    first = max(foreground, background) + 0.05
    second = min(foreground, background) + 0.05
    return first / second


def grayscale(value):
    if value > GRAY_MIDPOINT:
        return MAX_BYTE
    return 0


PERCENT_SCALE = 100
WEB_SAFE_STEP = 51


def to_percentage(fraction):
    return round(fraction * PERCENT_SCALE)


def hue_to_rgb(pending, q, t):
    if t < 0:
        return pending
    if t > 360:
        return q
    if t < 60:
        return pending + ((q - pending) * t) / 60
    if t < 180:
        return q
    if t < 240:
        return pending + ((q - pending) * (240 - t)) / 60
    return pending


def hsl_to_rgb(hue, saturation, lightness):
    h = (hue % 360 + 360) % 360
    s = clamp(saturation, 0, 100) / 100
    l = clamp(lightness, 0, 100) / 100
    q = l * (1 + s) if l < 0.5 else l + s - l * s
    p = 2 * l - q
    return [
        round(hue_to_rgb(p, q, h + 120) * MAX_BYTE / 100),
        round(hue_to_rgb(p, q, h) * MAX_BYTE / 100),
        round(hue_to_rgb(p, q, h - 120) * MAX_BYTE / 100),
    ]


def mix_color(left, right, weight):
    w = clamp(weight, 0, 100) / 100
    out = []
    for i in range(3):
        blended = round(left[i] * (1 - w) + right[i] * w)
        out.append(clamp(blended, 0, MAX_BYTE))
    return out


def channel_distance(left, right):
    total = 0
    for i in range(3):
        delta = left[i] - right[i]
        total += delta * delta
    return round((total ** 0.5) * 1000 / MAX_BYTE)


def snap_to_web_safe(value):
    rounded = round(clamp(value, 0, MAX_BYTE) / WEB_SAFE_STEP) * WEB_SAFE_STEP
    if rounded > 250:
        return MAX_BYTE
    return rounded
