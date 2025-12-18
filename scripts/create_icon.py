"""Create ICO using Windows Segoe MDL2 Assets font lightbulb glyph."""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


def create_lightbulb_icon(size: int) -> Image.Image:
    """Draw a lightbulb icon using Segoe MDL2 Assets font."""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Segoe MDL2 Assets lightbulb glyph: U+EA80
    lightbulb_char = "\uEA80"
    
    font_size = int(size * 0.85)
    font = ImageFont.truetype("C:/Windows/Fonts/segmdl2.ttf", font_size)
    
    # Center the glyph
    bbox = draw.textbbox((0, 0), lightbulb_char, font=font)
    x = (size - bbox[2] + bbox[0]) // 2 - bbox[0]
    y = (size - bbox[3] + bbox[1]) // 2 - bbox[1]
    
    draw.text((x, y), lightbulb_char, font=font, fill=(255, 255, 255, 255))
    return img


def main() -> None:
    ico_path = Path('src/lightbulb.ico')
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [create_lightbulb_icon(size) for size in sizes]
    
    images[0].save(
        str(ico_path),
        format='ICO',
        sizes=[(s, s) for s in sizes],
        append_images=images[1:]
    )
    print(f"Saved {ico_path}")


if __name__ == "__main__":
    main()
