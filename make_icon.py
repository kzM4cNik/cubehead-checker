from pathlib import Path
from PIL import Image, ImageDraw

img = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle((16, 16, 240, 240), radius=56, fill=(227, 180, 200, 255))
d.rounded_rectangle((58, 58, 122, 122), radius=12, fill=(58, 36, 51, 255))
d.rounded_rectangle((134, 58, 198, 122), radius=12, fill=(90, 58, 78, 255))
d.rounded_rectangle((58, 134, 122, 198), radius=12, fill=(90, 58, 78, 255))
d.rounded_rectangle((134, 134, 198, 198), radius=12, fill=(36, 24, 34, 255))
out = Path(__file__).with_name("cubehead.ico")
img.save(out, sizes=[(256, 256), (64, 64), (32, 32), (16, 16)])
print(out)
