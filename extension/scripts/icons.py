"""Rasterize the existing shield/check identity into Chromium-compatible PNG icons."""
from pathlib import Path
from PIL import Image, ImageDraw
root = Path(__file__).resolve().parents[1] / "icons"
root.mkdir(exist_ok=True)
for size in (16, 32, 48, 128):
    scale = 8
    image = Image.new("RGBA", (48*scale, 48*scale))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((0, 0, 48*scale-1, 48*scale-1), radius=14*scale, fill="#eaf3fb")
    draw.polygon([(x*scale, y*scale) for x,y in [(24,8),(37,13),(37,23),(35,30),(30,36),(24,40),(18,36),(13,30),(11,23),(11,13)]], fill="#3478c5")
    draw.line([(18*scale,24*scale),(22*scale,28*scale),(30*scale,19*scale)],fill="white",width=3*scale,joint="curve")
    image.resize((size,size),Image.Resampling.LANCZOS).save(root / f"icon{size}.png")
