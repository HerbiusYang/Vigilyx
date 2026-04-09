#!/usr/bin/env python3

from __future__ import annotations

import math
import random
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "marketing" / "social"

PALETTE = {
    "night": "#07111F",
    "ink": "#0C1B2C",
    "slate": "#18324A",
    "teal": "#16C6B0",
    "cyan": "#7DE7F5",
    "coral": "#FF5D5D",
    "apricot": "#FFB36B",
    "sand": "#F3EDE2",
    "cream": "#FFF8F0",
    "mist": "#D8E6F6",
    "line": "#1D3550",
}


def rgba(value: str, alpha: int = 255) -> tuple[int, int, int, int]:
    value = value.lstrip("#")
    if len(value) != 6:
        raise ValueError(f"expected 6-digit hex color, got {value}")
    return tuple(int(value[i : i + 2], 16) for i in range(0, 6, 2)) + (alpha,)


FONT_CANDIDATES = [
    "/System/Library/Fonts/Hiragino Sans GB.ttc",
    "/System/Library/Fonts/STHeiti Medium.ttc",
    "/System/Library/Fonts/STHeiti Light.ttc",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
]


def font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont:
    for candidate in FONT_CANDIDATES:
        path = Path(candidate)
        if path.exists():
            try:
                index = 1 if bold and path.suffix.lower() == ".ttc" else 0
                return ImageFont.truetype(str(path), size=size, index=index)
            except OSError:
                continue
    return ImageFont.load_default()


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def lerp_color(c1: tuple[int, int, int, int], c2: tuple[int, int, int, int], t: float) -> tuple[int, int, int, int]:
    return tuple(int(lerp(c1[i], c2[i], t)) for i in range(4))


def vertical_gradient(size: tuple[int, int], top: tuple[int, int, int, int], bottom: tuple[int, int, int, int]) -> Image.Image:
    width, height = size
    image = Image.new("RGBA", size)
    pixels = image.load()
    for y in range(height):
        t = y / max(1, height - 1)
        color = lerp_color(top, bottom, t)
        for x in range(width):
            pixels[x, y] = color
    return image


def add_radial_glow(base: Image.Image, center: tuple[int, int], radius: int, color: tuple[int, int, int, int], strength: float = 1.0) -> None:
    width, height = base.size
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    pixels = overlay.load()
    cx, cy = center
    for y in range(max(0, cy - radius), min(height, cy + radius)):
        for x in range(max(0, cx - radius), min(width, cx + radius)):
            distance = math.hypot(x - cx, y - cy)
            if distance >= radius:
                continue
            falloff = (1 - distance / radius) ** 2
            alpha = int(color[3] * falloff * strength)
            if alpha <= 0:
                continue
            pixels[x, y] = color[:3] + (alpha,)
    base.alpha_composite(overlay)


def draw_grid(draw: ImageDraw.ImageDraw, size: tuple[int, int], *, spacing: int, color: tuple[int, int, int, int]) -> None:
    width, height = size
    for x in range(0, width, spacing):
        draw.line((x, 0, x, height), fill=color, width=1)
    for y in range(0, height, spacing):
        draw.line((0, y, width, y), fill=color, width=1)


def add_noise(base: Image.Image, amount: int = 16, seed: int = 7) -> None:
    random.seed(seed)
    width, height = base.size
    pixels = base.load()
    for y in range(height):
        for x in range(width):
            grain = random.randint(-amount, amount)
            r, g, b, a = pixels[x, y]
            pixels[x, y] = (
                max(0, min(255, r + grain)),
                max(0, min(255, g + grain)),
                max(0, min(255, b + grain)),
                a,
            )


def rounded_panel(base: Image.Image, box: tuple[int, int, int, int], *, fill: tuple[int, int, int, int], radius: int = 30,
                  outline: tuple[int, int, int, int] | None = None, outline_width: int = 2,
                  shadow: tuple[int, int, int, int] | None = (0, 0, 0, 90), shadow_offset: tuple[int, int] = (0, 14),
                  shadow_blur: int = 26) -> None:
    x0, y0, x1, y1 = box
    width = x1 - x0
    height = y1 - y0
    if shadow is not None:
        shadow_layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
        sdraw = ImageDraw.Draw(shadow_layer)
        dx, dy = shadow_offset
        sdraw.rounded_rectangle((x0 + dx, y0 + dy, x1 + dx, y1 + dy), radius=radius, fill=shadow)
        shadow_layer = shadow_layer.filter(ImageFilter.GaussianBlur(shadow_blur))
        base.alpha_composite(shadow_layer)
    panel = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    pdraw = ImageDraw.Draw(panel)
    pdraw.rounded_rectangle((0, 0, width, height), radius=radius, fill=fill, outline=outline, width=outline_width)
    base.alpha_composite(panel, (x0, y0))


def text_box(draw: ImageDraw.ImageDraw, text: str, xy: tuple[int, int], label_font: ImageFont.FreeTypeFont,
             fill: tuple[int, int, int, int], spacing: int = 0) -> tuple[int, int, int, int]:
    bbox = draw.multiline_textbbox(xy, text, font=label_font, spacing=spacing)
    draw.multiline_text(xy, text, font=label_font, fill=fill, spacing=spacing)
    return bbox


def fit_text(draw: ImageDraw.ImageDraw, text: str, max_width: int, *, start_size: int, min_size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    size = start_size
    while size >= min_size:
        fnt = font(size, bold=bold)
        bbox = draw.multiline_textbbox((0, 0), text, font=fnt, spacing=max(10, size // 6))
        if bbox[2] - bbox[0] <= max_width:
            return fnt
        size -= 2
    return font(min_size, bold=bold)


def draw_pill(base: Image.Image, xy: tuple[int, int], text: str, *, fill: tuple[int, int, int, int], text_fill: tuple[int, int, int, int],
              pad_x: int = 24, pad_y: int = 14, text_size: int = 26, radius: int = 24,
              outline: tuple[int, int, int, int] | None = None) -> tuple[int, int, int, int]:
    draw = ImageDraw.Draw(base)
    fnt = font(text_size, bold=True)
    bbox = draw.textbbox((0, 0), text, font=fnt)
    width = bbox[2] - bbox[0] + pad_x * 2
    height = bbox[3] - bbox[1] + pad_y * 2
    box = (xy[0], xy[1], xy[0] + width, xy[1] + height)
    rounded_panel(base, box, fill=fill, radius=radius, outline=outline, outline_width=2, shadow=(0, 0, 0, 25), shadow_blur=14, shadow_offset=(0, 5))
    draw.text((xy[0] + pad_x, xy[1] + pad_y - 2), text, font=fnt, fill=text_fill)
    return box


def draw_connection(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int], *,
                    color: tuple[int, int, int, int], width: int = 6, arrow: bool = True) -> None:
    draw.line((start, end), fill=color, width=width)
    if arrow:
        angle = math.atan2(end[1] - start[1], end[0] - start[0])
        arrow_len = 16
        wing = math.pi / 7
        p1 = (
            end[0] - arrow_len * math.cos(angle - wing),
            end[1] - arrow_len * math.sin(angle - wing),
        )
        p2 = (
            end[0] - arrow_len * math.cos(angle + wing),
            end[1] - arrow_len * math.sin(angle + wing),
        )
        draw.polygon([end, p1, p2], fill=color)


def draw_polyline_arrow(draw: ImageDraw.ImageDraw, points: list[tuple[int, int]], *,
                        color: tuple[int, int, int, int], width: int = 6) -> None:
    if len(points) < 2:
        return
    for idx in range(len(points) - 1):
        draw.line((points[idx], points[idx + 1]), fill=color, width=width)
    draw_connection(draw, points[-2], points[-1], color=color, width=width, arrow=True)


def draw_database(base: Image.Image, box: tuple[int, int, int, int], *, fill: tuple[int, int, int, int], outline: tuple[int, int, int, int]) -> None:
    draw = ImageDraw.Draw(base)
    x0, y0, x1, y1 = box
    rounded_panel(base, box, fill=fill, radius=28, outline=outline, outline_width=3, shadow=(0, 0, 0, 50), shadow_blur=18, shadow_offset=(0, 8))
    top_h = 26
    draw.ellipse((x0 + 32, y0 + 22, x1 - 32, y0 + 22 + top_h), outline=outline, width=3, fill=rgba("#FFFFFF", 12))
    draw.line((x0 + 32, y0 + 35, x0 + 32, y1 - 25), fill=outline, width=3)
    draw.line((x1 - 32, y0 + 35, x1 - 32, y1 - 25), fill=outline, width=3)
    draw.arc((x0 + 32, y1 - 38, x1 - 32, y1 - 12), start=0, end=180, fill=outline, width=3)


def draw_icon_mail(draw: ImageDraw.ImageDraw, center: tuple[int, int], *, scale: float, color: tuple[int, int, int, int]) -> None:
    cx, cy = center
    w = int(104 * scale)
    h = int(72 * scale)
    x0 = cx - w // 2
    y0 = cy - h // 2
    x1 = x0 + w
    y1 = y0 + h
    draw.rounded_rectangle((x0, y0, x1, y1), radius=int(16 * scale), outline=color, width=max(2, int(4 * scale)))
    draw.line((x0 + 10 * scale, y0 + 12 * scale, cx, cy + 6 * scale), fill=color, width=max(2, int(4 * scale)))
    draw.line((x1 - 10 * scale, y0 + 12 * scale, cx, cy + 6 * scale), fill=color, width=max(2, int(4 * scale)))


def draw_icon_shield(draw: ImageDraw.ImageDraw, center: tuple[int, int], *, scale: float, color: tuple[int, int, int, int]) -> None:
    cx, cy = center
    pts = [
        (cx, cy - 58 * scale),
        (cx + 44 * scale, cy - 34 * scale),
        (cx + 38 * scale, cy + 28 * scale),
        (cx, cy + 60 * scale),
        (cx - 38 * scale, cy + 28 * scale),
        (cx - 44 * scale, cy - 34 * scale),
    ]
    draw.polygon(pts, outline=color, fill=None, width=max(2, int(4 * scale)))
    draw.line((cx - 18 * scale, cy + 4 * scale, cx - 2 * scale, cy + 22 * scale), fill=color, width=max(2, int(4 * scale)))
    draw.line((cx - 2 * scale, cy + 22 * scale, cx + 24 * scale, cy - 12 * scale), fill=color, width=max(2, int(4 * scale)))


def draw_icon_chart(draw: ImageDraw.ImageDraw, center: tuple[int, int], *, scale: float, color: tuple[int, int, int, int]) -> None:
    cx, cy = center
    base_x = cx - 40 * scale
    heights = [30, 54, 80]
    for idx, height in enumerate(heights):
        x0 = base_x + idx * 32 * scale
        draw.rounded_rectangle((x0, cy + 36 * scale - height, x0 + 18 * scale, cy + 36 * scale), radius=int(8 * scale), fill=color)


def draw_badge(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, *, fill: tuple[int, int, int, int], text_fill: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    fnt = font(24, bold=True)
    bbox = draw.textbbox((0, 0), text, font=fnt)
    width = bbox[2] - bbox[0] + 30
    height = bbox[3] - bbox[1] + 18
    draw.rounded_rectangle((xy[0], xy[1], xy[0] + width, xy[1] + height), radius=20, fill=fill)
    draw.text((xy[0] + 15, xy[1] + 9), text, font=fnt, fill=text_fill)
    return (xy[0], xy[1], xy[0] + width, xy[1] + height)


def draw_feature_card(base: Image.Image, box: tuple[int, int, int, int], *, title: str, body: str, accent: tuple[int, int, int, int], icon: str) -> None:
    draw = ImageDraw.Draw(base)
    rounded_panel(base, box, fill=rgba("#10233A", 230), radius=34, outline=rgba("#FFFFFF", 24), outline_width=2, shadow=(0, 0, 0, 70))
    x0, y0, x1, y1 = box
    draw.rounded_rectangle((x0 + 24, y0 + 24, x0 + 96, y0 + 96), radius=24, fill=accent)
    icon_draw = ImageDraw.Draw(base)
    icon_center = (x0 + 60, y0 + 60)
    if icon == "mail":
        draw_icon_mail(icon_draw, icon_center, scale=0.42, color=rgba("#07111F"))
    elif icon == "shield":
        draw_icon_shield(icon_draw, icon_center, scale=0.46, color=rgba("#07111F"))
    else:
        draw_icon_chart(icon_draw, icon_center, scale=0.52, color=rgba("#07111F"))

    title_font = font(32, bold=True)
    body_font = font(22)
    draw.text((x0 + 120, y0 + 28), title, font=title_font, fill=rgba("#FFF8F0"))
    draw.multiline_text((x0 + 120, y0 + 72), body, font=body_font, fill=rgba("#D8E6F6", 220), spacing=10)


def draw_cover() -> Path:
    size = (1440, 1920)
    base = vertical_gradient(size, rgba("#091320"), rgba("#07101A"))
    add_radial_glow(base, (1160, 260), 380, rgba(PALETTE["coral"], 175), 1.0)
    add_radial_glow(base, (220, 1580), 420, rgba(PALETTE["teal"], 110), 0.85)
    add_radial_glow(base, (1250, 1600), 280, rgba(PALETTE["apricot"], 70), 0.7)

    draw = ImageDraw.Draw(base)
    for x in range(96, 1350, 92):
        draw.line((x, 86, x, 1834), fill=rgba("#FFFFFF", 12), width=1)
    for y in range(96, 1834, 92):
        draw.line((92, y, 1348, y), fill=rgba("#FFFFFF", 10), width=1)
    add_noise(base, amount=6, seed=18)
    draw = ImageDraw.Draw(base)

    rounded_panel(base, (72, 70, 1368, 1848), fill=rgba("#FFFFFF", 8), radius=44, outline=rgba("#FFFFFF", 18), outline_width=2, shadow=None)

    left_x = 112
    title_width = 610
    panel_box = (822, 184, 1314, 1246)

    draw_pill(base, (left_x, 112), "Open Source / Email Security / Real-Time Analysis", fill=rgba(PALETTE["sand"], 238), text_fill=rgba(PALETTE["night"]), text_size=28, radius=24)
    draw.text((left_x, 220), "Vigilyx", font=font(66, bold=True), fill=rgba(PALETTE["cream"]))
    draw.text((left_x + 248, 240), "Email Threat Detection Platform", font=font(28, bold=True), fill=rgba(PALETTE["apricot"]))

    line1_font = fit_text(draw, "I Built an", title_width, start_size=118, min_size=98, bold=True)
    line2_font = fit_text(draw, "Email Security Platform", title_width, start_size=128, min_size=88, bold=True)
    draw.text((left_x, 344), "I Built an", font=line1_font, fill=rgba(PALETTE["cream"]))
    draw.text((left_x, 490), "Email Security Platform", font=line2_font, fill=rgba(PALETTE["coral"]))

    subtitle = "Supports Mirror passive mode and inline MTA Proxy mode\nCapture -> Parse -> Detect -> Alert -> Respond\nRust + React + Python AI"
    draw.multiline_text((left_x, 690), subtitle, font=font(34), fill=rgba(PALETTE["mist"]), spacing=18)

    bullets = [
        ("20+ parallel detection modules", rgba(PALETTE["teal"])),
        ("D-S evidence fusion + IOC", rgba(PALETTE["apricot"])),
        ("Live dashboard + SOAR actions", rgba(PALETTE["coral"])),
    ]
    bullet_y = 900
    for text, accent in bullets:
        draw.rounded_rectangle((left_x, bullet_y + 11, left_x + 18, bullet_y + 29), radius=8, fill=accent)
        draw.text((left_x + 34, bullet_y), text, font=font(32, bold=True), fill=rgba(PALETTE["cream"]))
        bullet_y += 72

    chip_specs = [
        ("20 threat modules", rgba(PALETTE["teal"], 235), rgba(PALETTE["night"])),
        ("Mirror / MTA Proxy", rgba(PALETTE["sand"], 245), rgba(PALETTE["night"])),
        ("D-S fusion + IOC", rgba(PALETTE["coral"], 230), rgba(PALETTE["cream"])),
        ("SOAR automation", rgba(PALETTE["slate"], 235), rgba(PALETTE["cream"])),
    ]
    chip_positions = [(left_x, 1140), (left_x + 270, 1140), (left_x, 1216), (left_x + 250, 1216)]
    for (text, fill, text_fill), pos in zip(chip_specs, chip_positions):
        draw_pill(base, pos, text, fill=fill, text_fill=text_fill, text_size=24, radius=22)

    rounded_panel(base, panel_box, fill=rgba("#0F2136", 240), radius=40, outline=rgba("#FFFFFF", 24), outline_width=2, shadow=(0, 0, 0, 110), shadow_blur=34, shadow_offset=(0, 20))
    px0, py0, px1, py1 = panel_box
    draw.rounded_rectangle((px0 + 28, py0 + 28, px1 - 28, py0 + 112), radius=24, fill=rgba(PALETTE["cream"], 245))
    draw.text((px0 + 46, py0 + 48), "Threat Dashboard", font=font(34, bold=True), fill=rgba(PALETTE["night"]))
    draw_badge(draw, (px1 - 182, py0 + 42), "LIVE", fill=rgba(PALETTE["coral"]), text_fill=rgba(PALETTE["cream"]))

    chart_box = (px0 + 28, py0 + 144, px1 - 28, py0 + 456)
    rounded_panel(base, chart_box, fill=rgba("#132A45", 240), radius=28, outline=rgba("#FFFFFF", 15), outline_width=2, shadow=None)
    cx0, cy0, cx1, cy1 = chart_box
    for gy in range(cy0 + 36, cy1 - 18, 48):
        draw.line((cx0 + 30, gy, cx1 - 30, gy), fill=rgba("#FFFFFF", 16), width=1)
    poly_points = [(cx0 + 44, cy1 - 62), (cx0 + 142, cy1 - 120), (cx0 + 246, cy1 - 88), (cx0 + 338, cy1 - 182), (cx1 - 58, cy1 - 244)]
    draw.line(poly_points, fill=rgba(PALETTE["coral"]), width=6, joint="curve")
    for point in poly_points:
        draw.ellipse((point[0] - 6, point[1] - 6, point[0] + 6, point[1] + 6), fill=rgba(PALETTE["cream"]))
    draw.text((cx0 + 34, cy0 + 24), "Live Risk Curve", font=font(28, bold=True), fill=rgba(PALETTE["mist"]))

    card_w = (px1 - px0 - 84) // 2
    left_card = (px0 + 28, py0 + 488, px0 + 28 + card_w, py0 + 712)
    right_card = (px0 + 56 + card_w, py0 + 488, px1 - 28, py0 + 712)
    draw_feature_card(base, left_card, title="Mail Sessions", body="SMTP / POP3 / IMAP\nCapture and protocol parsing", accent=rgba(PALETTE["teal"]), icon="mail")
    draw_feature_card(base, right_card, title="Detection Engine", body="Content / links / attachments\nNLP / IOC / fusion", accent=rgba(PALETTE["apricot"]), icon="shield")

    table_box = (px0 + 28, py0 + 744, px1 - 28, py1 - 28)
    rounded_panel(base, table_box, fill=rgba("#132A45", 235), radius=28, outline=rgba("#FFFFFF", 14), outline_width=2, shadow=None)
    tx0, ty0, tx1, ty1 = table_box
    draw.text((tx0 + 26, ty0 + 24), "Alerts and Response", font=font(30, bold=True), fill=rgba(PALETTE["cream"]))
    rows = [
        ("Phishing mail", "High", "Trigger response rules automatically"),
        ("Sender anomaly", "Medium", "Send to analyst review"),
        ("IOC hit", "High", "Push to dashboard and webhook"),
    ]
    row_y = ty0 + 88
    for idx, (name, level, detail) in enumerate(rows):
        if idx > 0:
            draw.line((tx0 + 24, row_y - 16, tx1 - 24, row_y - 16), fill=rgba("#FFFFFF", 12), width=1)
        draw.text((tx0 + 26, row_y), name, font=font(26, bold=True), fill=rgba(PALETTE["cream"]))
        badge_fill = rgba(PALETTE["coral"]) if level == "High" else rgba(PALETTE["sand"])
        badge_text = rgba(PALETTE["cream"]) if level == "High" else rgba(PALETTE["night"])
        draw_badge(draw, (tx0 + 194, row_y - 6), level, fill=badge_fill, text_fill=badge_text)
        draw.text((tx0 + 340, row_y + 2), detail, font=font(24), fill=rgba(PALETTE["mist"]))
        row_y += 72

    stat_boxes = [
        (112, 1478, 480, 1730),
        (536, 1478, 904, 1730),
        (960, 1478, 1328, 1730),
    ]
    stats = [
        ("Dual deployment", "Mirror / MTA", rgba(PALETTE["teal"])),
        ("Tech stack", "Rust + React + AI", rgba(PALETTE["sand"])),
        ("Value flow", "Observe -> Decide -> Respond", rgba(PALETTE["coral"])),
    ]
    for box, (title, body, accent) in zip(stat_boxes, stats):
        rounded_panel(base, box, fill=rgba("#102138", 225), radius=30, outline=rgba("#FFFFFF", 18), outline_width=2, shadow=(0, 0, 0, 60), shadow_blur=22, shadow_offset=(0, 12))
        x0, y0, x1, _ = box
        draw.rounded_rectangle((x0 + 26, y0 + 24, x0 + 90, y0 + 88), radius=20, fill=accent)
        draw.text((x0 + 112, y0 + 26), title, font=font(30, bold=True), fill=rgba(PALETTE["cream"]))
        draw.text((x0 + 112, y0 + 76), body, font=font(26), fill=rgba(PALETTE["mist"]))
        draw.text((x0 + 28, y0 + 132), "Fits product showcases and technical launch posts", font=font(22), fill=rgba(PALETTE["mist"], 180))

    draw.text((112, 1780), "Suggested launch-post flow: lead with product value, follow with architecture, finish with dashboard proof.", font=font(26), fill=rgba(PALETTE["mist"]))

    output = OUTPUT_DIR / "vigilyx-social-cover.png"
    base.save(output)
    return output


def draw_diagram_box(base: Image.Image, box: tuple[int, int, int, int], *, title: str, subtitle: str, fill: tuple[int, int, int, int],
                     outline: tuple[int, int, int, int], title_fill: tuple[int, int, int, int] = (255, 255, 255, 255),
                     subtitle_fill: tuple[int, int, int, int] | None = None) -> None:
    subtitle_fill = subtitle_fill or rgba("#D8E6F6", 230)
    rounded_panel(base, box, fill=fill, radius=30, outline=outline, outline_width=3, shadow=(0, 0, 0, 50), shadow_blur=18, shadow_offset=(0, 10))
    draw = ImageDraw.Draw(base)
    x0, y0, _, _ = box
    draw.text((x0 + 26, y0 + 20), title, font=font(34, bold=True), fill=title_fill)
    draw.multiline_text((x0 + 26, y0 + 68), subtitle, font=font(22), fill=subtitle_fill, spacing=8)


def draw_module_chip(base: Image.Image, xy: tuple[int, int], text: str, fill: tuple[int, int, int, int], text_fill: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    draw = ImageDraw.Draw(base)
    fnt = font(24, bold=True)
    bbox = draw.textbbox((0, 0), text, font=fnt)
    width = bbox[2] - bbox[0] + 34
    height = bbox[3] - bbox[1] + 18
    x0, y0 = xy
    draw.rounded_rectangle((x0, y0, x0 + width, y0 + height), radius=18, fill=fill)
    draw.text((x0 + 17, y0 + 9), text, font=fnt, fill=text_fill)
    return (x0, y0, x0 + width, y0 + height)


def distribute_chips(base: Image.Image, chips: Iterable[tuple[str, tuple[int, int, int, int], tuple[int, int, int, int]]],
                     area: tuple[int, int, int, int], *, gap_x: int = 16, gap_y: int = 18) -> None:
    x0, y0, x1, _ = area
    cursor_x = x0
    cursor_y = y0
    max_x = x1
    for text, fill, text_fill in chips:
        draw = ImageDraw.Draw(base)
        fnt = font(24, bold=True)
        bbox = draw.textbbox((0, 0), text, font=fnt)
        width = bbox[2] - bbox[0] + 34
        if cursor_x + width > max_x:
            cursor_x = x0
            cursor_y += 48 + gap_y
        draw_module_chip(base, (cursor_x, cursor_y), text, fill, text_fill)
        cursor_x += width + gap_x


def draw_architecture() -> Path:
    size = (1600, 2000)
    base = vertical_gradient(size, rgba("#F6F2EA"), rgba("#EAF0F8"))
    add_radial_glow(base, (1300, 260), 360, rgba(PALETTE["coral"], 85), 1.0)
    add_radial_glow(base, (260, 1720), 420, rgba(PALETTE["teal"], 72), 0.85)
    add_noise(base, amount=4, seed=29)
    draw = ImageDraw.Draw(base)

    draw.rounded_rectangle((56, 52, 1544, 1948), radius=40, outline=rgba("#16304A", 26), width=2)
    draw.text((96, 88), "Vigilyx Architecture", font=font(70, bold=True), fill=rgba(PALETTE["night"]))
    draw.text((100, 176), "Dual-mode email security platform: ingest -> message bus -> detection -> storage / alerting / response", font=font(30), fill=rgba("#35516B"))
    draw_pill(base, (1186, 86), "Rust / React / Python AI", fill=rgba(PALETTE["night"]), text_fill=rgba(PALETTE["cream"]), text_size=24, radius=24)

    draw_pill(base, (100, 242), "INGEST", fill=rgba(PALETTE["night"]), text_fill=rgba(PALETTE["cream"]), text_size=22, radius=18)
    draw_pill(base, (100, 822), "ANALYZE", fill=rgba(PALETTE["night"]), text_fill=rgba(PALETTE["cream"]), text_size=22, radius=18)
    draw_pill(base, (100, 1340), "DELIVER", fill=rgba(PALETTE["night"]), text_fill=rgba(PALETTE["cream"]), text_size=22, radius=18)

    mode_left = (100, 298, 740, 540)
    mode_right = (860, 298, 1500, 540)
    bus_box = (390, 622, 1210, 764)
    engine_box = (120, 882, 1480, 1238)
    storage_box = (120, 1410, 500, 1648)
    api_box = (610, 1410, 990, 1648)
    response_box = (1100, 1410, 1480, 1648)
    ai_box = (120, 1726, 520, 1888)
    value_box = (610, 1726, 1480, 1888)

    draw_diagram_box(base, mode_left, title="Mode A · Mirror Passive Mode",
                     subtitle="Sniffer (libpcap)\nSMTP / POP3 / IMAP / HTTP capture\nNon-intrusive integration into live mail traffic",
                     fill=rgba("#10243B", 242), outline=rgba(PALETTE["cyan"], 120))
    draw_diagram_box(base, mode_right, title="Mode B · Inline MTA Proxy",
                     subtitle="vigilyx-mta\nSMTP proxy + TLS + inline verdict\nSupports accept / reject / quarantine",
                     fill=rgba("#193022", 238), outline=rgba(PALETTE["apricot"], 135))
    draw_diagram_box(base, bus_box, title="Message Bus · Redis / Valkey Pub/Sub",
                     subtitle="Channel: session:new\nDecouples ingest and analysis layers for async scaling and consumers",
                     fill=rgba(PALETTE["slate"], 236), outline=rgba(PALETTE["cyan"], 96))

    rounded_panel(base, engine_box, fill=rgba("#0C1D32", 244), radius=36, outline=rgba(PALETTE["night"], 70), outline_width=3, shadow=(0, 0, 0, 70), shadow_blur=22, shadow_offset=(0, 14))
    ex0, ey0, ex1, ey1 = engine_box
    draw.text((ex0 + 36, ey0 + 28), "Security Engine · Threat DAG + D-S Fusion", font=font(50, bold=True), fill=rgba(PALETTE["cream"]))
    draw.multiline_text((ex0 + 36, ey0 + 98), "16-20 modules run in parallel across content, links, attachments, identity signals, NLP, IOC, DLP, and temporal analysis.\nThe fusion layer handles correlation, risk grading, confidence aggregation, and circuit breakers.", font=font(28), fill=rgba(PALETTE["mist"]), spacing=10)

    chips = [
        ("header_scan", rgba(PALETTE["coral"], 228), rgba(PALETTE["cream"])),
        ("content_scan", rgba(PALETTE["sand"], 246), rgba(PALETTE["night"])),
        ("link_scan", rgba(PALETTE["teal"], 236), rgba(PALETTE["night"])),
        ("link_reputation", rgba("#BDE6FF", 246), rgba(PALETTE["night"])),
        ("attach_content", rgba("#FFE0B8", 246), rgba(PALETTE["night"])),
        ("semantic_scan", rgba(PALETTE["coral"], 228), rgba(PALETTE["cream"])),
        ("identity_anomaly", rgba("#D9D2FF", 246), rgba(PALETTE["night"])),
        ("anomaly_detect", rgba("#C3F1E6", 246), rgba(PALETTE["night"])),
        ("IOC cache", rgba("#FFE7E0", 246), rgba(PALETTE["night"])),
        ("YARA / AV", rgba("#FFF1BF", 246), rgba(PALETTE["night"])),
        ("DLP", rgba("#C8ECFF", 246), rgba(PALETTE["night"])),
        ("Temporal Analyzer", rgba("#C9F5D5", 246), rgba(PALETTE["night"])),
        ("D-S Murphy", rgba(PALETTE["apricot"], 236), rgba(PALETTE["night"])),
        ("SOAR rules", rgba(PALETTE["sand"], 246), rgba(PALETTE["night"])),
    ]
    distribute_chips(base, chips, (ex0 + 36, ey0 + 196, ex1 - 40, ey1 - 40), gap_x=14, gap_y=16)

    draw_diagram_box(base, storage_box, title="PostgreSQL",
                     subtitle="Sessions, verdicts, IOC, allowlists, feedback\nSupports historical search and analytics",
                     fill=rgba("#12253D", 242), outline=rgba(PALETTE["cyan"], 110))
    draw_diagram_box(base, api_box, title="API + Frontend",
                     subtitle="axum REST + WebSocket\nReact dashboard / alerts / session detail\nPresents live threat posture to operators",
                     fill=rgba("#132942", 240), outline=rgba(PALETTE["teal"], 128))
    draw_diagram_box(base, response_box, title="SOAR + Downstream",
                     subtitle="Mail alerting / webhook / automation\nReject / quarantine / relay\nFits an enterprise response loop",
                     fill=rgba("#312219", 238), outline=rgba(PALETTE["coral"], 140))
    draw_diagram_box(base, ai_box, title="AI Service",
                     subtitle="Python FastAPI\nZero-shot mDeBERTa plus optional fine-tuned model\nAdds semantic phishing detection",
                     fill=rgba("#241C3B", 240), outline=rgba("#C8BAFF"))
    draw_diagram_box(base, value_box, title="External Value",
                     subtitle="Works both as a passive monitor and as a mail-entry decision point.\nSuitable for open-source launch material, product demos, enterprise security narratives, and startup positioning.",
                     fill=rgba(PALETTE["cream"], 242), outline=rgba("#C5D5E6"), title_fill=rgba(PALETTE["night"]), subtitle_fill=rgba("#35516B"))

    draw.ellipse((632, 354, 704, 426), fill=rgba("#FFFFFF", 16), outline=rgba(PALETTE["cyan"], 90), width=2)
    draw.ellipse((1392, 354, 1464, 426), fill=rgba("#FFFFFF", 16), outline=rgba(PALETTE["apricot"], 90), width=2)
    draw_icon_mail(draw, (668, 390), scale=0.34, color=rgba(PALETTE["cyan"]))
    draw_icon_shield(draw, (1428, 390), scale=0.38, color=rgba(PALETTE["apricot"]))

    line_color = rgba("#20384E", 180)
    draw_polyline_arrow(draw, [(420, 540), (420, 586), (620, 586), (620, 622)], color=rgba(PALETTE["cyan"], 190), width=7)
    draw_polyline_arrow(draw, [(1180, 540), (1180, 586), (980, 586), (980, 622)], color=rgba(PALETTE["apricot"], 190), width=7)
    draw_polyline_arrow(draw, [(800, 764), (800, 882)], color=line_color, width=7)
    draw.line((800, 1238, 800, 1322), fill=line_color, width=7)
    draw.line((310, 1322, 1290, 1322), fill=line_color, width=7)
    draw_polyline_arrow(draw, [(310, 1322), (310, 1410)], color=line_color, width=7)
    draw_polyline_arrow(draw, [(800, 1322), (800, 1410)], color=line_color, width=7)
    draw_polyline_arrow(draw, [(1290, 1322), (1290, 1410)], color=line_color, width=7)
    draw_polyline_arrow(draw, [(320, 1726), (320, 1686), (84, 1686), (84, 1058), (120, 1058)], color=rgba(PALETTE["teal"], 168), width=6)

    output = OUTPUT_DIR / "vigilyx-architecture-diagram.png"
    base.save(output)
    return output


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    cover = draw_cover()
    architecture = draw_architecture()
    print(cover)
    print(architecture)


if __name__ == "__main__":
    main()
